"""PC-only immutable MTA copied-factory-UI builder; no device/runtime actions.

Derives only the verified v2.4.0 /NaviPanel.qml QRC slot, using the enumerator
and same-slot algorithm from BiliP011-v0.1/host/build_awake_trial.py. The old
Bili directories and original ELF are read-only. No Qt SDK, service, worker,
guardian, credential file, radio admission or runtime test is provided here.

No CLI path/options: all inputs and both destination roots are fixed below.
Failure preserves any exclusively created partial output for diagnosis.
"""
import hashlib
import json
import pathlib
import re
import secrets
import stat
import struct
import sys
import zlib


BASE = pathlib.Path(__file__).resolve().parents[1]
PROJECT = BASE.parents[1]
ORIGINAL = PROJECT / '06_Firmware/backups/v2.4.0-20260923-162730/files/Z03'
ORIGINAL_PIN = (4103844, 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a')
FORMAL = BASE / 'candidate/formal-ui-v1/device'
ENTRY = BASE / 'candidate/formal-ui-native-v1/device'
OUTPUT = BASE / 'out'
REMOTE_ROOT = '/mnt/data/p011-toolbox/mta-ui'
QRC_OFFSETS = (0x1a3acc, 0x1a5efc, 0x1a9f54)
NAV_OFFSET = 1946708
NAV_SLOT = 1580
FORMAL_PINS = (
    ('MtaPage.qml', 26088, '2e63016d806f890703c5d361b35cc80d2e092e55a2714088f27dcb948ef5c44e'),
    ('MtaHost.qml', 6205, '371f705136fb1e03aec7d283120f6915b798edd4b96cdec670f29c971d508380'),
    ('MtaButton.qml', 757, '5abb4dabbd735ef4a071e8e10a65cf5c946e505cceb2373a12fa5f54827d1339'),
    ('MtaLabel.qml', 351, 'e6298ebb141e4eba23b7acd1dee6900c141d1065ed194be953d1b3daff77eaa3'),
    ('MtaKeyboard.qml', 5344, '3241344572163deff5bc195cfb06dc5647f76861c03736f99a331d5bb53ef661'),
    ('MtaTheme.js', 261, 'b795cd24c1bae4c9423c6c9c3e45303b0494c267a897715c4f8eab14f8f12f2c'),
)
ENTRY_PINS = (
    ('Bridge.qml', 961, 'b20e5ff48a31fb6588774e39db22749b39c0093030e4e64ede370e2d40abf0c2'),
    ('FormalEntry.qml', 5287, '256d9a7b16b34e3b6e05069f9d028c0fb20338371113b4042126ae1febba5d59'),
)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def read_pinned(path, length, digest):
    require(not path.is_symlink(), 'Linked source input')
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_size == length, 'Source size/type differs')
    raw = path.read_bytes()
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'Source changed while reading')
    require(len(raw) == length and sha256(raw) == digest, 'Source pin differs')
    return raw


def enumerate_qrc(raw):
    """Read the fixed original register literals and every actual resource."""
    offsets = tuple(struct.unpack_from('<I', raw, literal - 0x10000)[0] + pc - 0x10000
                    for literal, pc in ((0x36b40, 0x36b30), (0x36b3c, 0x36b2c),
                                        (0x36b38, 0x36b24)))
    require(offsets == QRC_OFFSETS, 'QRC register offsets differ')
    tree, names, data_at = offsets
    resources = {}
    visited = set()

    def walk(index, parent):
        require(index not in visited and 0 <= index and tree + index * 22 + 22 <= names,
                'QRC tree index')
        visited.add(index)
        at = tree + index * 22
        no, flags = struct.unpack_from('>IH', raw, at)
        pos = names + no
        require(names <= pos and pos + 6 <= data_at, 'QRC name offset')
        length = struct.unpack_from('>H', raw, pos)[0]
        require(pos + 6 + length * 2 <= data_at, 'QRC name extent')
        name = raw[pos + 6:pos + 6 + length * 2].decode('utf-16-be')
        path = parent + '/' + name if index else ''
        if flags & 2:
            count, first = struct.unpack_from('>II', raw, at + 6)
            require(count < 1000, 'QRC directory count')
            for child in range(first, first + count):
                walk(child, path)
        else:
            require(path not in resources, 'Duplicate QRC resource')
            offset = data_at + struct.unpack_from('>I', raw, at + 10)[0]
            require(data_at <= offset and offset + 4 <= len(raw), 'QRC data offset')
            size = struct.unpack_from('>I', raw, offset)[0]
            require(offset + 4 + size <= len(raw), 'QRC data extent')
            body = raw[offset + 4:offset + 4 + size]
            if flags & 1:
                require(len(body) >= 4, 'QRC compressed header')
                size_raw = struct.unpack_from('>I', body)[0]
                body = zlib.decompress(body[4:])
                require(len(body) == size_raw, 'QRC decompressed size')
            resources[path] = dict(offset=offset, size=size, flags=flags, body=body,
                                   record=raw[offset:offset + 4 + size])

    walk(0, '')
    require(len(resources) == 400, 'Expected 400 QRC resources')
    return resources


def patch_factory_ui(original, remote):
    resources = enumerate_qrc(original)
    require('/NaviPanel.qml' in resources and '/main.qml' in resources, 'Missing factory scene roots')
    target = resources['/NaviPanel.qml']
    require(target['flags'] & 1 and target['offset'] == NAV_OFFSET and target['size'] == NAV_SLOT,
            'NaviPanel slot differs')
    main = resources['/main.qml']['body']
    for pattern in (rb'onSceneSourceChanged\s*:', rb'inner\s*\.\s*visible\s*=\s*false\b',
                    rb'scene\s*\.\s*parent\s*=\s*main\b', rb'scene\s*\.\s*anchors\s*\.\s*fill\s*=\s*main\b'):
        require(re.search(pattern, main) is not None, 'Factory scene route differs')
    # As in the audited Bili builder: preserve tokens/comments and line endings;
    # remove leading indentation only, then inject one fixed private Loader.
    source = target['body'].decode('utf-8')
    compact = ''.join(line.lstrip(' \t') for line in source.splitlines(keepends=True))
    require(compact.count('id: navi\n') == 1, 'Ambiguous NaviPanel root')
    loader = 'Loader { source: "file://' + remote + '/Bridge.qml";onLoaded:item.navigator=navi }\n'
    qml = compact.replace('id: navi\n', 'id: navi\n' + loader, 1).encode('utf-8')
    packed = struct.pack('>I', len(qml)) + zlib.compress(qml, 9)
    require(len(packed) <= NAV_SLOT, 'NaviPanel compressed slot too small')
    require(zlib.decompress(packed[4:]) == qml, 'Compressed QML readback differs')
    block = struct.pack('>I', len(packed)) + packed + bytes(NAV_SLOT - len(packed))
    end = NAV_OFFSET + 4 + NAV_SLOT
    candidate = original[:NAV_OFFSET] + block + original[end:]
    require(len(candidate) == len(original) and candidate[:NAV_OFFSET] == original[:NAV_OFFSET] and
            candidate[end:] == original[end:], 'ELF outside slot differs')
    readback = enumerate_qrc(candidate)
    require(set(readback) == set(resources), 'QRC resource inventory differs')
    require(readback['/NaviPanel.qml']['offset'] == NAV_OFFSET and
            readback['/NaviPanel.qml']['flags'] == target['flags'] and
            readback['/NaviPanel.qml']['body'] == qml, 'Patched QRC readback differs')
    unchanged = 0
    for path, old in resources.items():
        if path == '/NaviPanel.qml':
            continue
        new = readback[path]
        require(new == old, 'Unrelated QRC resource differs')
        unchanged += 1
    require(unchanged == 399, 'Expected 399 original resource records')
    return candidate, qml, len(packed)


def render_entry(template, session, remote):
    source = template.decode('utf-8')
    require('@REMOTE@' in source, 'Missing fixed remote placeholder')
    source = source.replace('@SESSION@', session).replace('@REMOTE@', remote)
    require(re.search(r'@[A-Z_]+@', source) is None, 'Unresolved entry placeholder')
    return source.encode('utf-8')


def write_new(path, raw):
    with path.open('xb') as output:
        written = output.write(raw)
        require(written == len(raw), 'Partial candidate write')
    require(path.read_bytes() == raw, 'Candidate file readback differs')


def build():
    require(sys.platform == 'win32', 'This fixed builder is development-PC-only')
    require(len(sys.argv) == 1, 'This builder accepts no CLI options or paths')
    require(OUTPUT.is_dir() and not OUTPUT.is_symlink() and OUTPUT.resolve() == OUTPUT,
            'Fixed output root differs')
    original = read_pinned(ORIGINAL, *ORIGINAL_PIN)
    files = {}
    inputs = []
    for name, length, digest in FORMAL_PINS:
        files['device/' + name] = read_pinned(FORMAL / name, length, digest)
        inputs.append(dict(path='candidate/formal-ui-v1/device/' + name, bytes=length, sha256=digest))
    templates = {}
    for name, length, digest in ENTRY_PINS:
        templates[name] = read_pinned(ENTRY / name, length, digest)
        inputs.append(dict(path='candidate/formal-ui-native-v1/device/' + name, bytes=length, sha256=digest))
    session = secrets.token_hex(12)
    require(re.fullmatch(r'[0-9a-f]{24}', session) is not None, 'Invalid fresh session identity')
    remote = REMOTE_ROOT + '/' + session
    candidate, nav_qml, used = patch_factory_ui(original, remote)
    files['Z03.mta-ui-candidate'] = candidate
    for name, template in templates.items():
        files[name] = render_entry(template, session, remote)
    require(len(files) == 9 and 'credentials.json' not in files, 'Unexpected distribution input')
    manifest = ''.join(sha256(raw) + ' ' + str(len(raw)) + ' ' + name + '\n'
                       for name, raw in sorted(files.items())).encode('ascii')
    out = OUTPUT / ('mta-ui-' + session)
    # Exclusive creation: neither old candidates nor an existing path is reused.
    out.mkdir(exist_ok=False)
    (out / 'device').mkdir(exist_ok=False)
    for name, raw in sorted(files.items()):
        write_new(out / name, raw)
    write_new(out / 'SOURCE.sha256', manifest)
    write_new(out / 'NaviPanel.embedded.qml', nav_qml)
    result = dict(
        schema='p011-mta-copied-factory-ui-v1-pc-build', evidence_level='PC_BUILD_ONLY',
        session=session, remote=remote, original_path=str(ORIGINAL),
        original_bytes=len(original), original_sha256=ORIGINAL_PIN[1],
        candidate_bytes=len(candidate), candidate_sha256=sha256(candidate),
        source_manifest_sha256=sha256(manifest), source_manifest_files=9,
        changed_resource='/NaviPanel.qml', resources_verified=400,
        other_resources_original_bytes=399, record_offset=NAV_OFFSET,
        slot_bytes=NAV_SLOT, used_bytes=used, elf_total_length_unchanged=True,
        elf_outside_slot_unchanged=True, compressed_qml_readback=True,
        factory_scene_route_source_checked=True, inputs=inputs,
        builder_sha256=sha256(pathlib.Path(__file__).read_bytes()),
        source_algorithm='BiliP011-v0.1/host/build_awake_trial.py single QRC slot',
        credentials_policy=dict(runtime_basename='credentials.json',
                                runtime_fields=['session', 'endpoint', 'token'],
                                runtime_file_created=False, included_in_SOURCE=False,
                                included_in_public_logs_or_ZIP=False),
        geometry='parent-owned 800x268; no additional offset or rotation',
        bootstrap_allowed=False, host_preview=False, service_owner_connected=False,
        worker_implemented=False, guardian_implemented=False, qml_runtime_verified=False,
        device_tested=False, original_files_changed=False, startup_changed=False,
        radio_admission_issued=False, receive_tested=False, send_tested=False,
        phone_interop_verified=False, stock_restoration_verified=False,
    )
    encoded = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode('utf-8')
    write_new(out / 'build-result.json', encoded)
    print(json.dumps(result, indent=2, sort_keys=True))
    print('BUNDLE=' + str(out))
    return out


if __name__ == '__main__':
    build()
