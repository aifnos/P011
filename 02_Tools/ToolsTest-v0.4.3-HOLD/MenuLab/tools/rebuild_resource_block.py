#!/usr/bin/env python3
"""Rebuild ONLY the offline resource patch from a QML file; no device I/O.
Run this on a development PC with Python 3 (not the pen's stripped Python).
The source Z03 version is pinned; output must be a new empty directory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib

EXPECTED = 'e6760ad70cc17b089fd3dded68e58feb545a6b77f3f653b90d7427104b626997'
OFFSET = 0x1c625c
SLOT_PAYLOAD = 1580

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--original', required=True, type=Path)
    p.add_argument('--qml', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    binary = args.original.read_bytes()
    if hashlib.sha256(binary).hexdigest() != EXPECTED:
        raise SystemExit('Unexpected original executable. Refusing to patch.')
    qml = args.qml.read_bytes()
    qml.decode('utf-8')  # Fail on wrong encoding. Deliberately no unsafe auto-minifier.
    data = struct.pack('>I', len(qml)) + zlib.compress(qml, 9)
    if len(data) > SLOT_PAYLOAD:
        raise SystemExit('Compressed QML needs {} bytes; slot allows {}. Do not overwrite adjacent resources.'.format(len(data), SLOT_PAYLOAD))
    if args.out.exists():
        raise SystemExit('Output directory exists. Choose a new directory.')
    block = struct.pack('>I', len(data)) + data + bytes(SLOT_PAYLOAD-len(data))
    candidate = binary[:OFFSET] + block + binary[OFFSET+4+SLOT_PAYLOAD:]
    if zlib.decompress(candidate[OFFSET+8:OFFSET+4+len(data)]) != qml:
        raise SystemExit('Roundtrip failed.')
    args.out.mkdir(parents=True)
    (args.out/'Z03.menu-candidate').write_bytes(candidate)
    (args.out/'NaviPanel.resource-block.bin').write_bytes(block)
    (args.out/'NaviPanel.embedded.qml').write_bytes(qml)
    result = dict(original_sha256=EXPECTED, candidate_sha256=hashlib.sha256(candidate).hexdigest(),
                  record_offset=OFFSET, record_size=len(block), payload_size=len(data),
                  padding=SLOT_PAYLOAD-len(data), input_unchanged=True, device_tested=False)
    (args.out/'build-result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
