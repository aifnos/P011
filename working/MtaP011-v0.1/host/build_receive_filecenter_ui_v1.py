"""PC-only immutable receive/FileCenter UI builder; never accesses the P011.

One fresh 24-hex session and output directory per explicit invocation. Frozen
16 UI inputs (14 QML and two JS), original Bridge and original Z03 are read only.
Only three source-authenticated definitions from the pinned old PC helper are
compiled in a new private namespace: require/enumerate_qrc/patch_factory_ui.
No old builder main/build, SDK, Qt process, ADB, worker, credential, radio or
runtime validator is executed. Failed exclusive outputs remain for diagnosis.
"""
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import struct
import sys
import zlib


BASE = Path(__file__).resolve().parents[1]
PROJECT = BASE.parents[1]
ORIGINAL_RELATIVE = '06_Firmware/backups/v2.4.0-20260923-162730/files/Z03'
ORIGINAL = PROJECT / ORIGINAL_RELATIVE
ORIGINAL_PIN = (4103844, 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a')
HELPER = BASE / 'host/build_formal_ui_candidate_v1.py'
HELPER_PIN = (11889, '5215ebff474016262900c0599355bfa9b6e48e5960ed0a20f07f17428f87e70c')
SOURCE_ROOT = BASE / 'candidate/receive-filecenter-v1/device'
BRIDGE = BASE / 'candidate/formal-ui-native-v1/device/Bridge.qml'
BRIDGE_PIN = (961, 'b20e5ff48a31fb6588774e39db22749b39c0093030e4e64ede370e2d40abf0c2')
OUTPUT = BASE / 'out'
REMOTE_ROOT = '/mnt/data/p011-toolbox/mta-ui'
QRC_OFFSETS = (0x1a3acc, 0x1a5efc, 0x1a9f54)
NAV_OFFSET = 1946708
NAV_SLOT = 1580
SOURCE_BUDGET = 262144
SOURCE_PINS = (
    ('FormalEntry.qml', 4018, '5fac51356309e02a3b97c6e4c5c6626e379ba5b7d2c6c96eb55a6441a190f5f7'),
    ('ReceiveComposition.qml', 401, '6f1701b31faa62822dcf3e51afd74e001c000d588c6df1cba8b6700e8320ac39'),
    ('mta/MtaButton.qml', 757, '5abb4dabbd735ef4a071e8e10a65cf5c946e505cceb2373a12fa5f54827d1339'),
    ('mta/MtaHost.qml', 6341, 'e610b343fe4058bb89d45ee65cb14bdd4471363b56a737d85ab5c51297e42f11'),
    ('mta/MtaKeyboard.qml', 5344, '3241344572163deff5bc195cfb06dc5647f76861c03736f99a331d5bb53ef661'),
    ('mta/MtaLabel.qml', 351, 'e6298ebb141e4eba23b7acd1dee6900c141d1065ed194be953d1b3daff77eaa3'),
    ('mta/MtaPage.qml', 26088, '2e63016d806f890703c5d361b35cc80d2e092e55a2714088f27dcb948ef5c44e'),
    ('mta/MtaTheme.js', 261, 'b795cd24c1bae4c9423c6c9c3e45303b0494c267a897715c4f8eab14f8f12f2c'),
    ('toolbox/Button.qml', 665, 'ef4f1f83c198ae40e56982eec7d1ee87d36185fae9bbf1b15ea8853b64dcb015'),
    ('toolbox/ExtensionPage.qml', 10109, 'e2ea4ac96acda29509df272001599be9410d5989a2400bfaef73901378062093'),
    ('toolbox/FilesPage.qml', 11639, '5f1b4255211f4369f64dfc24eddcc565d6e6a64f708e181e15b68828376bd1e1'),
    ('toolbox/Label.qml', 269, '4f109dd7591c7363dc95883ca2c13cf43c3b9c9f461d72238d1567a52bd949fc'),
    ('toolbox/MtaEmbedded.qml', 6543, 'cf5e0c34eae957e8f6ebd5c0641ff7d6d177cb8407db3957049255e6e94e095b'),
    ('toolbox/NativeIcon.qml', 1999, '08baa5b5b7176fc5abaa59c5ef261f0474c05565838a68fa6c110aed80867f4d'),
    ('toolbox/Theme.js', 244, '308cc441d29a5d39e61e0418ad0b4dfbb3efa2be6ce0bf6e80577c73479d2edb'),
    ('toolbox/VideoPane.qml', 705, 'e09873e298aa6b762051ab866ca82ea5b44f0d2988ab97e6ad6719c947934651'),
)
STAGE_DIRECTORIES = ('', 'mta', 'toolbox')


def require(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def directory(path):
    """Reject linked/reparse ancestors; this never creates or repairs a path."""
    for node in reversed((path,) + tuple(path.parents)):
        value = node.lstat()
        require(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
                not getattr(value, 'st_file_attributes', 0) & 0x400, 'linked_or_unknown_directory')
    return metadata(path.lstat())


def read_pinned(path, size, sha):
    directory(path.parent)
    require(type(size) is int and 0 < size <= 5 * 1024 * 1024 and
            type(sha) is str and re.fullmatch(r'[0-9a-f]{64}', sha) is not None, 'source_pin_not_frozen')
    value = path.lstat()
    require(stat.S_ISREG(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
            not getattr(value, 'st_file_attributes', 0) & 0x400 and value.st_size == size,
            'source_file_identity')
    before = metadata(value)
    with path.open('rb') as stream:
        opened = metadata(os.fstat(stream.fileno()))
        same = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                opened[3:6] == before[3:6]) if os.name == 'nt' else opened == before
        require(same, 'source_open_identity')
        raw = stream.read(size + 1)
        require(metadata(os.fstat(stream.fileno())) == opened, 'source_changed_during_read')
    require(metadata(path.lstat()) == before and len(raw) == size and digest(raw) == sha,
            'source_pin_changed')
    return raw


def relative_name(value):
    return (type(value) is str and re.fullmatch(r'[A-Za-z0-9_./-]{1,128}', value) is not None and
            not PurePosixPath(value).is_absolute() and '\\' not in value and
            all(part not in ('', '.', '..') for part in value.split('/')))


def source_inventory():
    """Exact 16-file/three-directory source closure, with no symlink traversal."""
    directory(SOURCE_ROOT)
    expected = {name for name, size, sha in SOURCE_PINS}
    require(len(SOURCE_PINS) == len(expected) == 16 and all(relative_name(name) for name in expected),
            'source_inventory_contract')
    found = set()
    for relative in STAGE_DIRECTORIES:
        root = SOURCE_ROOT if relative == '' else SOURCE_ROOT / relative
        directory(root)
        names = os.scandir(root)
        try:
            for count, entry in enumerate(names):
                require(count < 32, 'source_inventory_budget')
                value = entry.stat(follow_symlinks=False)
                require(not stat.S_ISLNK(value.st_mode) and
                        not getattr(value, 'st_file_attributes', 0) & 0x400, 'source_inventory_link')
                path = entry.name if relative == '' else relative + '/' + entry.name
                if path in ('mta', 'toolbox'):
                    require(relative == '' and stat.S_ISDIR(value.st_mode), 'source_inventory_directory')
                else:
                    require(stat.S_ISREG(value.st_mode) and path in expected and path not in found,
                            'source_inventory_extra')
                    found.add(path)
        finally:
            names.close()
    require(found == expected, 'source_inventory_incomplete')


def load_algorithms(helper_raw):
    """Only the pinned helper's three pure definition nodes, not its module/build."""
    require((len(helper_raw), digest(helper_raw)) == HELPER_PIN, 'helper_pin')
    tree = ast.parse(helper_raw.decode('utf-8'), feature_version=(3, 5))
    wanted = ('require', 'enumerate_qrc', 'patch_factory_ui')
    nodes = []
    for name in wanted:
        matches = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
        require(len(matches) == 1 and not matches[0].decorator_list, 'helper_definition')
        nodes.append(matches[0])
    expected = dict(QRC_OFFSETS=QRC_OFFSETS, NAV_OFFSET=NAV_OFFSET, NAV_SLOT=NAV_SLOT)
    actual = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in expected:
                    require(target.id not in actual, 'helper_literal_duplicate')
                    actual[target.id] = ast.literal_eval(node.value)
    require(actual == expected, 'helper_literal_changed')
    scope = dict(__name__='receive_filecenter_fixed_patch', struct=struct, zlib=zlib, re=re,
                 QRC_OFFSETS=QRC_OFFSETS, NAV_OFFSET=NAV_OFFSET, NAV_SLOT=NAV_SLOT)
    subset = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(subset, str(HELPER), 'exec'), scope)
    require('build' not in scope and '__main__' not in scope, 'old_builder_executed')
    return scope['patch_factory_ui'], scope['enumerate_qrc']


def render_template(raw, session, remote, session_required):
    source = raw.decode('utf-8')
    require(source.count('@REMOTE@') == 1 and
            (source.count('@SESSION@') == 1 if session_required else '@SESSION@' not in source),
            'template_contract')
    source = source.replace('@REMOTE@', remote).replace('@SESSION@', session)
    require(re.search(r'@[A-Z_]+@', source) is None, 'template_unresolved')
    return source.encode('utf-8')


def write_new(path, raw):
    require(type(raw) is bytes and len(raw) <= 5 * 1024 * 1024, 'output_budget')
    directory(path.parent)
    with path.open('xb') as stream:
        require(stream.write(raw) == len(raw), 'output_short_write')
    value = path.lstat()
    require(stat.S_ISREG(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
            not getattr(value, 'st_file_attributes', 0) & 0x400 and
            value.st_size == len(raw) and path.read_bytes() == raw, 'output_readback')


def build():
    require(sys.platform == 'win32' and os.name == 'nt', 'development_pc_only')
    require(len(sys.argv) == 1, 'fixed_builder_no_arguments')
    require(BASE == Path(r'D:\project\P011\working\MtaP011-v0.1') and
            OUTPUT.is_dir() and OUTPUT.resolve() == OUTPUT, 'fixed_workspace')
    directory(OUTPUT)
    # Fail closed before creating an output directory if any source pin is draft.
    require(all(type(size) is int and size > 0 and type(sha) is str and
                re.fullmatch(r'[0-9a-f]{64}', sha) is not None for name, size, sha in SOURCE_PINS),
            'source_pin_not_frozen')
    source_inventory()
    original = read_pinned(ORIGINAL, *ORIGINAL_PIN)
    helper = read_pinned(HELPER, *HELPER_PIN)
    bridge = read_pinned(BRIDGE, *BRIDGE_PIN)
    files = {}
    inputs = []
    for name, size, sha in SOURCE_PINS:
        raw = read_pinned(SOURCE_ROOT / name, size, sha)
        require(name.endswith(('.qml', '.js')) and b'\0' not in raw, 'source_text_type')
        raw.decode('utf-8')
        files[name] = raw
        inputs.append(dict(path='candidate/receive-filecenter-v1/device/' + name, bytes=size, sha256=sha))
    require(sum(len(raw) for raw in files.values()) + len(bridge) <= SOURCE_BUDGET, 'source_text_budget')
    source_inventory()
    session = secrets.token_hex(12)
    require(re.fullmatch(r'[0-9a-f]{24}', session) is not None, 'fresh_session')
    remote = REMOTE_ROOT + '/' + session
    patch, enumerate_resources = load_algorithms(helper)
    candidate, nav, used = patch(original, remote)
    end = NAV_OFFSET + 4 + NAV_SLOT
    require(len(candidate) == ORIGINAL_PIN[0] and candidate[:NAV_OFFSET] == original[:NAV_OFFSET] and
            candidate[end:] == original[end:] and 0 < used <= NAV_SLOT, 'elf_same_slot')
    old_resources, new_resources = enumerate_resources(original), enumerate_resources(candidate)
    require(set(old_resources) == set(new_resources) and len(old_resources) == 400 and
            sum(new_resources[name] == value for name, value in old_resources.items() if name != '/NaviPanel.qml') == 399,
            'qrc_original_399')
    files['Z03.mta-ui-candidate'] = candidate
    files['Bridge.qml'] = render_template(bridge, session, remote, False)
    files['FormalEntry.qml'] = render_template(files['FormalEntry.qml'], session, remote, True)
    require(len(files) == 18 and all(relative_name(name) for name in files) and
            'credentials.json' not in files and
            all(re.search(rb'@[A-Z_]+@', raw) is None for name, raw in files.items() if name != 'Z03.mta-ui-candidate'),
            'payload_inventory')
    pins = tuple((name, len(raw), digest(raw)) for name, raw in sorted(files.items()))
    source = ''.join(sha + ' ' + str(size) + ' ' + name + '\n' for name, size, sha in pins).encode('ascii')
    require(len(source) <= 4096 and len(source.splitlines()) == 18, 'source_manifest_budget')
    stage_files = files.copy()
    stage_files['SOURCE.sha256'] = source
    stage_pins = tuple((name, len(raw), digest(raw)) for name, raw in sorted(stage_files.items()))
    require(len(stage_pins) == 19 and sum(row[1] for row in stage_pins) <= 5 * 1024 * 1024,
            'stage_budget')
    out = OUTPUT / ('mta-ui-' + session)
    out.mkdir(exist_ok=False)
    (out / 'mta').mkdir(exist_ok=False)
    (out / 'toolbox').mkdir(exist_ok=False)
    for name, raw in sorted(stage_files.items()):
        write_new(out / name, raw)
    # These three PC diagnostics are not staged and must fail target inventory if copied.
    write_new(out / 'NaviPanel.embedded.qml', nav)
    stage = dict(schema='p011-receive-filecenter-ui-stage-v1', session=session, remote=remote,
        payload_file_count=18, staged_file_count=19,
        source_manifest=dict(path='SOURCE.sha256', bytes=len(source), sha256=digest(source),
                             format='sha256 space decimal-bytes space relative-path LF'),
        directories=[dict(path=name, mode='0700') for name in STAGE_DIRECTORIES],
        files=[dict(path=name, bytes=size, sha256=sha,
                    mode='0500' if name == 'Z03.mta-ui-candidate' else '0400') for name, size, sha in stage_pins],
        excluded_pc_files=['NaviPanel.embedded.qml', 'stage-manifest.json', 'build-result.json'],
        credentials_in_stage=False, font_files_bundled=False)
    write_new(out / 'stage-manifest.json', (json.dumps(stage, indent=2, sort_keys=True) + '\n').encode('ascii'))
    result = dict(schema='p011-receive-filecenter-ui-pc-build-v1', evidence_level='PC_BUILD_ONLY',
        session=session, remote=remote, original_path=ORIGINAL_RELATIVE,
        original_bytes=len(original), original_sha256=ORIGINAL_PIN[1],
        candidate_bytes=len(candidate), candidate_sha256=digest(candidate),
        source_manifest_bytes=len(source), source_manifest_sha256=digest(source),
        source_manifest_files=18, staged_file_count=19, staged_directory_count=3,
        source_ui_files=16, source_qml_files=14, source_js_files=2,
        changed_resource='/NaviPanel.qml', resources_verified=400, other_resources_original_bytes=399,
        record_offset=NAV_OFFSET, slot_bytes=NAV_SLOT, used_bytes=used,
        elf_total_length_unchanged=True, elf_outside_slot_unchanged=True, compressed_qml_readback=True,
        reused_helper_path='host/build_formal_ui_candidate_v1.py', reused_helper_sha256=HELPER_PIN[1],
        reused_helper_definitions=['require', 'enumerate_qrc', 'patch_factory_ui'], old_builder_invoked=False,
        inputs=inputs + [dict(path='candidate/formal-ui-native-v1/device/Bridge.qml',
                             bytes=BRIDGE_PIN[0], sha256=BRIDGE_PIN[1])],
        builder_sha256=digest(Path(__file__).read_bytes()),
        geometry='parent-owned 800x268; no additional offset or rotation',
        credentials_policy=dict(runtime_basename='credentials.json',
            runtime_fields=['session', 'endpoint', 'token', 'toolboxEndpoint', 'toolboxToken'],
            runtime_file_created=False, included_in_SOURCE=False, included_in_public_logs_or_ZIP=False),
        original_files_changed=False, startup_changed=False, device_tested=False,
        qml_runtime_verified=False, native_component_verified=False, companion_connected=False,
        receive_tested=False, send_tested=False, radio_admission_issued=False,
        phone_interop_verified=False, stock_restoration_verified=False)
    write_new(out / 'build-result.json', (json.dumps(result, indent=2, sort_keys=True) + '\n').encode('ascii'))
    print(json.dumps(result, indent=2, sort_keys=True))
    print('BUNDLE=' + str(out))
    return out


if __name__ == '__main__':
    build()
