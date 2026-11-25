#!/usr/bin/env python3
"""PC-only, version-pinned two-resource builder. No device I/O or target execution.

Reads only patch/SetBtPage.readable.qml and the reviewed NaviPanel files.
Without --out, updates the package's generated Bluetooth files and patch manifest.
With --out, writes an immutable new build directory without changing the package.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib

EXPECTED = 'e6760ad70cc17b089fd3dded68e58feb545a6b77f3f653b90d7427104b626997'
ORIGINAL_SIZE = 4001256
NAVI_PATH = '/NaviPanel.qml'
NAVI_OFFSET, NAVI_RECORD = 0x1c625c, 1584
BT_PATH = '/ZybQmlFiles/ZybSet/SetBtPage.qml'
BT_OFFSET, BT_RECORD, BT_PAYLOAD = 0x21e225, 3992, 3988
BT_ORIGINAL_QML = '8b37d58f19c686891942c387bf448e16bad13d1d2b560d54609b227747a59901'
BT_QML_FILE = 'patch/SetBtPage.embedded.qml'
BT_BLOCK_FILE = 'patch/SetBtPage.resource-block.bin'
sha = lambda b: hashlib.sha256(b).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def trim_external_whitespace(text):
    """Trim only line-edge space/tab proven outside strings and comments.

    Retain line endings and all string/comment contents, including multiline
    strings/templates, escapes and block comments. This is not a JS minifier.
    """
    output = []
    state, escaped = 'normal', False
    for line in text.splitlines(keepends=True):
        safe = []
        i = 0
        while i < len(line):
            c = line[i]
            safe.append(state == 'normal' and c in ' \t')
            if state == 'line':
                if c in '\r\n':
                    state = 'normal'
            elif state == 'block':
                if line.startswith('*/', i):
                    safe.append(False); i += 1; state = 'normal'
            elif state != 'normal':
                if escaped:
                    escaped = False
                elif c == '\\':
                    escaped = True
                elif c == state:
                    state = 'normal'
            elif line.startswith('//', i):
                safe.append(False); i += 1; state = 'line'
            elif line.startswith('/*', i):
                safe.append(False); i += 1; state = 'block'
            elif c in "\"'`":
                state = c
            i += 1
        left, right = 0, len(line)
        while left < right and safe[left]:
            left += 1
        ending = ''
        while right > left and line[right - 1] in '\r\n':
            right -= 1
        ending = line[right:]
        while right > left and safe[right - 1]:
            right -= 1
        output.append(line[left:right] + ending)
    require(state in ('normal', 'line'), 'Unclosed string or block comment in readable QML')
    return ''.join(output)


def resource_map(binary):
    result, seen = {}, set()
    def walk(index, prefix):
        require(index not in seen, 'Resource tree cycle')
        seen.add(index)
        at = 0x18e8d4 + 22 * index
        no, flags = struct.unpack_from('>IH', binary, at)
        pos = 0x190d04 + no
        length = struct.unpack_from('>H', binary, pos)[0]
        name = binary[pos + 6:pos + 6 + length * 2].decode('utf-16-be')
        path = prefix + '/' + name if index else ''
        if flags & 2:
            count, first = struct.unpack_from('>II', binary, at + 6)
            require(count <= 10000, 'Invalid tree count')
            for child in range(first, first + count):
                walk(child, path)
        else:
            rel = struct.unpack_from('>I', binary, at + 10)[0]
            record = 0x194d5c + rel
            length = struct.unpack_from('>I', binary, record)[0]
            data = binary[record + 4:record + 4 + length]
            require(len(data) == length, 'Truncated resource')
            if flags & 1:
                expanded = struct.unpack_from('>I', data)[0]
                data = zlib.decompress(data[4:])
                require(len(data) == expanded, 'Invalid resource expansion length')
            result[path] = data
    walk(0, '')
    return result


def validate_manifest_ranges(manifest):
    require(manifest['original_sha256'] == EXPECTED and manifest['original_size'] == ORIGINAL_SIZE,
            'Manifest does not identify pinned original Z03')
    require(manifest['qml_resource'] == NAVI_PATH and manifest['record_offset'] == NAVI_OFFSET
            and manifest['original_record_size'] == NAVI_RECORD
            and manifest['original_qml_sha256'] == '68915d92ca6cc084779e106d65e1c62b2e7bb64d735c0676298795d7ce04f42b',
            'NaviPanel fixed slot mismatch')
    bt = manifest.get('bluetooth_patch')
    if bt is not None:
        fields = dict(qml_resource=BT_PATH, record_offset=BT_OFFSET,
                      original_record_size=BT_RECORD, original_payload_size=BT_PAYLOAD,
                      embedded_qml_file=BT_QML_FILE, resource_block_file=BT_BLOCK_FILE,
                      original_qml_sha256=BT_ORIGINAL_QML)
        require(all(bt.get(k) == v for k, v in fields.items()), 'Bluetooth fixed slot/path mismatch')
    require(NAVI_OFFSET + NAVI_RECORD <= BT_OFFSET and BT_OFFSET + BT_RECORD <= ORIGINAL_SIZE,
            'Patch ranges overlap or exceed original')


def decode_block(block, record_size):
    require(len(block) == record_size, 'Resource block length mismatch')
    payload = struct.unpack_from('>I', block)[0]
    require(4 <= payload <= record_size - 4, 'Invalid compressed payload size')
    expanded = struct.unpack_from('>I', block, 4)[0]
    decoder = zlib.decompressobj()
    qml = decoder.decompress(block[8:payload + 4]) + decoder.flush()
    require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
            'Compressed resource has trailing or incomplete stream')
    require(len(qml) == expanded, 'Expanded QML size mismatch')
    require(not any(block[payload + 4:]), 'Resource slot padding is not zero')
    return qml


def verify_candidate(original, candidate, qmls):
    require(len(candidate) == len(original), 'Candidate size changed')
    cursor = 0
    for offset, length in ((NAVI_OFFSET, NAVI_RECORD), (BT_OFFSET, BT_RECORD)):
        require(original[cursor:offset] == candidate[cursor:offset], 'Bytes outside fixed slots changed')
        cursor = offset + length
    require(original[cursor:] == candidate[cursor:], 'Bytes outside fixed slots changed')
    before, after = resource_map(original), resource_map(candidate)
    require(len(before) == 400 and before.keys() == after.keys(), 'QRC resource tree changed')
    changed = [key for key in before if before[key] != after[key]]
    require(set(changed) == {NAVI_PATH, BT_PATH}, 'Expected exactly two changed resources')
    require(all(after[key] == value for key, value in qmls.items()), 'Embedded resource differs from reviewed QML')
    require(sha(before[BT_PATH]) == BT_ORIGINAL_QML, 'Original Bluetooth QML mismatch')
    require(original[:52] == candidate[:52], 'ELF header changed')
    phoff = struct.unpack_from('<I', original, 28)[0]
    phsize, phcount = struct.unpack_from('<HH', original, 42)
    require(original[phoff:phoff + phsize * phcount] == candidate[phoff:phoff + phsize * phcount],
            'ELF program headers changed')
    shoff = struct.unpack_from('<I', original, 32)[0]
    shsize, shcount = struct.unpack_from('<HH', original, 46)
    require(original[shoff:shoff + shsize * shcount] == candidate[shoff:shoff + shsize * shcount],
            'ELF section headers changed')
    executable = []
    for i in range(shcount):
        entry = struct.unpack_from('<10I', original, shoff + shsize * i)
        if entry[2] & 4:
            offset, size = entry[4:6]
            require(original[offset:offset + size] == candidate[offset:offset + size], 'Executable section changed')
            executable.append(dict(index=i, offset=offset, length=size))
    return changed, executable


def build(package, original):
    require(sha(original) == EXPECTED and len(original) == ORIGINAL_SIZE, 'Unexpected original executable. Refusing to patch.')
    m = json.loads((package / 'patch/manifest.json').read_text(encoding='utf-8-sig'))
    validate_manifest_ranges(m)
    require(struct.unpack_from('>I', original, NAVI_OFFSET)[0] == NAVI_RECORD - 4,
            'Original NaviPanel record size mismatch')
    require(struct.unpack_from('>I', original, BT_OFFSET)[0] == BT_PAYLOAD,
            'Original Bluetooth record size mismatch')
    nav = (package / 'patch/NaviPanel.resource-block.bin').read_bytes()
    navqml = (package / 'patch/NaviPanel.embedded.qml').read_bytes()
    require(sha(nav) == m['block_sha256'] and sha(navqml) == m['embedded_qml_sha256'], 'NaviPanel block/QML hash mismatch')
    require(decode_block(nav, NAVI_RECORD) == navqml, 'NaviPanel block does not contain reviewed QML')
    readable = (package / 'patch/SetBtPage.readable.qml').read_bytes().decode('utf-8')
    qml = trim_external_whitespace(readable).encode('utf-8')
    payload = struct.pack('>I', len(qml)) + zlib.compress(qml, 9)
    require(len(payload) <= BT_PAYLOAD, 'Compressed QML needs {} bytes; slot allows {}.'.format(len(payload), BT_PAYLOAD))
    block = struct.pack('>I', len(payload)) + payload + bytes(BT_PAYLOAD - len(payload))
    require(decode_block(block, BT_RECORD) == qml, 'Bluetooth QML block roundtrip failed')
    candidate = bytearray(original)
    candidate[NAVI_OFFSET:NAVI_OFFSET + NAVI_RECORD] = nav
    candidate[BT_OFFSET:BT_OFFSET + BT_RECORD] = block
    candidate = bytes(candidate)
    changed, executable = verify_candidate(original, candidate, {NAVI_PATH: navqml, BT_PATH: qml})
    m.update(candidate_sha256=sha(candidate), candidate_size=len(candidate),
             other_resources_unchanged=398, changed_resources=changed,
             executable_sections_unchanged=executable, device_tested=False)
    m['bluetooth_patch'] = dict(qml_resource=BT_PATH, record_offset=BT_OFFSET,
        record_offset_hex=hex(BT_OFFSET), original_record_size=BT_RECORD,
        original_payload_size=BT_PAYLOAD, original_qml_sha256=BT_ORIGINAL_QML,
        embedded_qml_file=BT_QML_FILE, resource_block_file=BT_BLOCK_FILE,
        embedded_qml_sha256=sha(qml), block_sha256=sha(block),
        new_payload_size=len(payload), unused_padding=BT_PAYLOAD-len(payload), device_tested=False)
    return m, qml, block, candidate


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--original', required=True, type=Path)
    p.add_argument('--package-dir', type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument('--out', type=Path)
    args = p.parse_args()
    if args.out is not None and args.out.exists():
        raise SystemExit('Output directory exists. Choose a new directory.')
    try:
        original = args.original.read_bytes()
        m, qml, block, candidate = build(args.package_dir, original)
        require(args.original.read_bytes() == original, 'Original changed during build')
        target = args.out if args.out is not None else args.package_dir / 'patch'
        target.mkdir(parents=True, exist_ok=args.out is None)
        (target / 'SetBtPage.embedded.qml').write_bytes(qml)
        (target / 'SetBtPage.resource-block.bin').write_bytes(block)
        (target / 'manifest.json').write_text(json.dumps(m, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        if args.out is not None:
            (target / 'Z03.menu-candidate').write_bytes(candidate)
        print(json.dumps(dict(status='BUILT_OFFLINE_ONLY', candidate_sha256=m['candidate_sha256'],
            changed_resources=m['changed_resources'], unchanged_resources=398,
            bluetooth_payload_size=m['bluetooth_patch']['new_payload_size'],
            bluetooth_padding=m['bluetooth_patch']['unused_padding'], original_unchanged=True), ensure_ascii=False, indent=2))
    except (ValueError, KeyError, OSError, struct.error, zlib.error) as error:
        raise SystemExit(str(error))


if __name__ == '__main__':
    main()
