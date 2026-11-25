"""Build an immutable, private legacy browser settings install package. No ADB."""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import zipfile

HERE = Path(__file__).resolve().parent
BROWSER = HERE.parents[1]
NEW = "b7d3ae6d7696364970613f0a23f8eeabec39f90bdb6f807ccb6c59221b4e70d8"
OLD = "3526b379c4083092c9c282d4d749d2e5c72d89e56730bf08c975e3222ed42896"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def build(page_dir: Path, out: Path, z03: Path):
    if page_dir.is_symlink() or not page_dir.is_dir():
        raise ValueError("Expected an existing page source directory")
    files = {}
    allowed = {".qml", ".js", ".html", ".css", ".svg", ".png", ".jpg", ".webp"}
    for source in sorted(page_dir.rglob("*")):
        if source.is_symlink():
            raise ValueError("Page symlinks are not accepted")
        if source.is_dir():
            continue
        relative = source.relative_to(page_dir).as_posix()
        if source.suffix.lower() not in allowed or source.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("Unexpected page resource: " + relative)
        if relative.split("/")[0] == "_install":
            raise ValueError("Page resource overlaps installer administration")
        files["payload/" + relative] = source.read_bytes()
    if "payload/BrowserPage.qml" not in files or sum(map(len, files.values())) > 16 * 1024 * 1024:
        raise ValueError("Expected a small BrowserPage.qml payload")
    for name in ("device_install.py",):
        files[name] = (HERE / name).read_bytes()
        ast.parse(files[name].decode("utf-8"), feature_version=(3, 5))
    files["p011_json.py"] = (BROWSER / "runtime/p011_json.py").read_bytes()
    files["Z03.patched"] = z03.read_bytes()
    if sha(files["Z03.patched"]) != NEW:
        raise ValueError("Legacy Z03 candidate differs")
    config = {"schema": "p011.browser.legacy-install.v1", "old_z03_sha256": OLD,
              "new_z03_sha256": NEW, "kernel": "vendor-qt5", "startup_changes": False,
              "entry": "file:///mnt/data/p011-browser/settings/legacy/BrowserPage.qml"}
    files["install-config.py"] = (repr(config) + "\n").encode("ascii")
    manifest = {"schema": "p011.browser.legacy-package.v1", "files": {
        name: {"bytes": len(data), "sha256": sha(data)} for name, data in sorted(files.items())}}
    manifest_bytes = (repr(manifest) + "\n").encode("ascii")
    identity = sha(manifest_bytes)
    destination = out / ("legacy-package-" + identity[:16])
    destination.mkdir(parents=True, exist_ok=False)
    files["package-manifest.py"] = manifest_bytes
    for name, data in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    archive = destination.with_suffix(".private.zip")
    with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED) as handle:
        for name in sorted(files):
            handle.writestr(name, files[name])
    with zipfile.ZipFile(archive) as handle:
        if handle.testzip() is not None or any(handle.read(name) != data for name, data in files.items()):
            raise ValueError("Package ZIP readback failed")
    checksum = sha(archive.read_bytes())
    archive.with_suffix(archive.suffix + ".sha256").write_text(checksum + "  " + archive.name + "\n", encoding="ascii")
    result = {"schema": "p011.browser.legacy-host-package.v1", "package": str(destination),
              "manifest_sha256": identity, "zip": str(archive), "zip_sha256": checksum,
              "files": len(files), "payload_bytes": sum(len(value) for name, value in files.items() if name.startswith("payload/")),
              "z03_sha256": NEW, "device_touched": False}
    (destination.parent / (destination.name + ".json")).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (HERE / "selected-package.txt").write_text(str(destination.resolve()) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--page-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=HERE / "out")
    parser.add_argument("--z03", type=Path, default=HERE / "out/legacy-settings-b7d3ae6d7696364970613f0a/Z03.patched")
    args = parser.parse_args()
    print(json.dumps(build(args.page_dir, args.out, args.z03), ensure_ascii=False))


if __name__ == "__main__":
    main()
