"""PC-only, fixed-resource settings entry builder. Never opens ADB.

Input is the already installed formal Bili Z03 identity, not the factory image.
Only SetMainPage's existing compressed record may change. Original bytes,
including the Bili feedback record, are preserved everywhere else.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[2]
INPUT_PIN = "3526b379c4083092c9c282d4d749d2e5c72d89e56730bf08c975e3222ed42896"
MAIN_PIN = "d8b200e4d31b077f264b551eda55de975957476c4acb978ef4c55e21fb3748b3"
TREE, NAMES, DATA = 0x1A3ACC, 0x1A5EFC, 0x1A9F54
RESOURCE = "/ZybQmlFiles/ZybSet/SetMainPage.qml"
FEEDBACK = "/ZybQmlFiles/ZybSet/SetUserReport.qml"
ENTRY = "file:///mnt/data/p011-browser/settings/BrowserEntry.qml"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def resource_map(binary: bytes) -> dict:
    rows, seen = {}, set()

    def visit(index: int, parent: str) -> None:
        at = TREE + index * 22
        if index in seen or index < 0 or not TREE <= at < at + 22 <= NAMES:
            raise ValueError("Unexpected QRC tree")
        seen.add(index)
        name_at, flags = struct.unpack_from(">IH", binary, at)
        pos = NAMES + name_at
        length = struct.unpack_from(">H", binary, pos)[0]
        if not NAMES <= pos < pos + 6 + length * 2 <= DATA:
            raise ValueError("Unexpected QRC name")
        name = binary[pos + 6:pos + 6 + length * 2].decode("utf-16-be")
        path = parent + "/" + name if index else ""
        if flags & 2:
            count, first = struct.unpack_from(">II", binary, at + 6)
            if count > 1000:
                raise ValueError("Unexpected QRC child count")
            for child in range(first, first + count):
                visit(child, path)
            return
        offset = DATA + struct.unpack_from(">I", binary, at + 10)[0]
        size = struct.unpack_from(">I", binary, offset)[0]
        raw = binary[offset + 4:offset + 4 + size]
        if len(raw) != size:
            raise ValueError("Truncated QRC record")
        body = raw
        if flags & 1:
            decoder = zlib.decompressobj()
            body = decoder.decompress(raw[4:]) + decoder.flush()
            if (not decoder.eof or decoder.unused_data or decoder.unconsumed_tail
                    or len(body) != struct.unpack_from(">I", raw)[0]):
                raise ValueError("Unexpected compressed QRC data")
        if path in rows:
            raise ValueError("Duplicate QRC resource")
        rows[path] = dict(offset=offset, size=size, flags=flags, body=body,
                          record=bytes(binary[offset:offset + 4 + size]))

    visit(0, "")
    if len(rows) != 400:
        raise ValueError("Unexpected resource count")
    return rows


def settings_qml(original: bytes) -> bytes:
    if sha(original) != MAIN_PIN:
        raise ValueError("Original settings resource differs")
    lines = original.splitlines(keepends=True)
    anchors = [line for line in lines if b"SetDevInfo.qml" in line]
    if len(anchors) != 1 or b"p011-browser" in original:
        raise ValueError("Settings append anchor is ambiguous")
    entry = (b'        ListElement { name: qsTr("\\u6d4f\\u89c8\\u5668"); '
             b'icon: "qrc:/images/set_main_wifi.png"; circle: false; source: "'
             + ENTRY.encode("ascii") + b'" }\n')
    expanded = original.replace(anchors[0], anchors[0] + entry, 1)
    # Trim only line indentation and empty lines. String contents and original
    # model order remain unchanged; the compact record fits the existing slot.
    compact = b"\n".join(line.strip() for line in expanded.splitlines() if line.strip()) + b"\n"
    if compact.count(b"ListElement {") != 17:
        raise ValueError("Expected the original 16 items plus one browser item")
    if compact.count(ENTRY.encode("ascii")) != 1:
        raise ValueError("Browser entry identity differs")
    for index in (1, 4, 12):
        if compact.count(('setModel.setProperty(%d,' % index).encode("ascii")) != original.count(
                ('setModel.setProperty(%d,' % index).encode("ascii")):
            raise ValueError("Existing settings index changed")
    return compact


def build(original: bytes) -> tuple[bytes, bytes, dict]:
    if sha(original) != INPUT_PIN:
        raise ValueError("Input must be the pinned current formal Bili Z03")
    before = resource_map(original)
    target = before[RESOURCE]
    if (target["offset"], target["size"], target["flags"]) != (0x226120, 1763, 1):
        raise ValueError("Settings QRC slot differs")
    qml = settings_qml(target["body"])
    packed = struct.pack(">I", len(qml)) + zlib.compress(qml, 9)
    if len(packed) > target["size"]:
        raise ValueError("New settings page exceeds its fixed compressed slot")
    offset, slot = target["offset"], target["size"]
    block = struct.pack(">I", len(packed)) + packed + bytes(slot - len(packed))
    candidate = original[:offset] + block + original[offset + 4 + slot:]
    after = resource_map(candidate)
    changed = [key for key in before if before[key]["body"] != after[key]["body"]]
    if changed != [RESOURCE] or len(candidate) != len(original):
        raise ValueError("Unexpected resource changes")
    if (original[:offset] != candidate[:offset]
            or original[offset + 4 + slot:] != candidate[offset + 4 + slot:]):
        raise ValueError("Bytes outside the settings QRC record changed")
    if before[FEEDBACK] != after[FEEDBACK]:
        raise ValueError("Existing formal Bili feedback record changed")
    unchanged = [key for key in before if key != RESOURCE and before[key] == after[key]]
    if len(unchanged) != 399:
        raise ValueError("Other resources differ")
    result = {
        "schema": "p011.browser.settings-candidate.v1",
        "status": "PC_CANDIDATE_ONLY_DEVICE_INSTALL_PENDING",
        "input_sha256": INPUT_PIN,
        "candidate_sha256": sha(candidate),
        "binary_bytes": len(candidate),
        "changed_resource": RESOURCE,
        "original_settings_sha256": MAIN_PIN,
        "settings_sha256": sha(qml),
        "record_offset": offset,
        "record_slot_bytes": slot,
        "record_used_bytes": len(packed),
        "resources_verified": 400,
        "other_resource_records_unchanged": 399,
        "outside_resource_record_unchanged": True,
        "elf_headers_and_code_unchanged": True,
        "formal_bili_feedback_record_unchanged": True,
        "formal_bili_feedback_sha256": sha(before[FEEDBACK]["body"]),
        "browser_model_index": 16,
        "previous_model_order_unchanged": True,
        "entry_source": ENTRY,
        "device_touched": False,
        "settings_navigation_verified": False,
        "browser_runtime_verified": False,
    }
    return candidate, qml, result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=PROJECT / "working/BiliP011-v0.1/formal/out/P011-Bili-Formal-v4-adb-sysv-20261014/Z03.patched")
    parser.add_argument("--out", type=Path, default=HERE / "out")
    args = parser.parse_args()
    if args.input.is_symlink() or not args.input.is_file():
        raise ValueError("Input must be a regular local file")
    candidate, qml, result = build(args.input.read_bytes())
    destination = args.out / ("settings-entry-" + result["candidate_sha256"][:24])
    destination.mkdir(parents=True, exist_ok=False)
    outputs = {"Z03.patched": candidate, "SetMainPage.qml": qml}
    for name, data in outputs.items():
        (destination / name).write_bytes(data)
    result["files"] = {name: {"bytes": len(data), "sha256": sha(data)}
                       for name, data in outputs.items()}
    (destination / "candidate.json").write_text(json.dumps(result, ensure_ascii=True,
        indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(destination), **result}, ensure_ascii=True, sort_keys=True))


if __name__ == "__main__":
    main()
