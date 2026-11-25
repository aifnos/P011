"""PC-only immutable sender/FileCenter UI-v5 builder; never accesses the P011.

One fresh 24-hex session and output directory per explicit invocation. Frozen
16 UI inputs (14 QML and two JS), original Bridge and original Z03 are read only.
Only two source-authenticated definitions from the pinned old PC helper are
compiled in a new private namespace: require/enumerate_qrc. The new same-slot patch supplies only the original vk.
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
SOURCE_ROOT = BASE / 'candidate/formal-send-filecenter-ui-v5/device'
BRIDGE = BASE / 'candidate/formal-send-filecenter-ui-v5/entry/Bridge.qml'
BRIDGE_PIN = (2514, '1565b10e40a6d44025e662f0a5c6a0695d95e2545026e48f70e319a120dfc134')
OUTPUT = BASE / 'out'
REMOTE_ROOT = '/mnt/data/p011-toolbox/mta-ui'
QRC_OFFSETS = (0x1a3acc, 0x1a5efc, 0x1a9f54)
NAV_OFFSET = 1946708
NAV_SLOT = 1580
SOURCE_BUDGET = 262144
SOURCE_PINS = (
    ('FormalEntry.qml', 4019, '798ebacd073769e06045921779fe8d8a765a69f3f2f1a2418cd2d8f2ff731232'),
    ('ReceiveComposition.qml', 402, 'a739489cfaf77f9500e3ac3585f34d9fadf152de92770a2ced525bfbb41eb360'),
    ('mta/MtaButton.qml', 758, '7e1d4e378b8e3293e617f4dc432cce3c70ae7fe377f2ea26950aa9bb11393bff'),
    ('mta/MtaHost.qml', 6342, 'c151b0bd7a9b686f5110eef968c50506d9a814c14b5d9db9ccebfe8f05d7b322'),
    ('mta/MtaKeyboard.qml', 5345, '2de31e8cde68ab6ff76f4da85c386d5cddb466cccefb809987dddfce2f8c40cc'),
    ('mta/MtaLabel.qml', 352, '77caf248c2f83ed50f5221082084e5af360d08fc917df98eb84449e24903bd75'),
    ('mta/MtaPage.qml', 26769, '1084ea1a5a906bbf0f56ea20df031ea9b4a1fd0931879e80cd6dfb475f7eabc2'),
    ('mta/MtaTheme.js', 262, '5848aa8bf1dab57cfe590dd80da1122eb819c75c1f208f69ad4184bf669a99ff'),
    ('toolbox/Button.qml', 666, 'bc8878dfd7c50512934bb9a9a0aab2e54ed84ac86967d3db49d38cd87f3b6216'),
    ('toolbox/ExtensionPage.qml', 10110, 'e7fac81643238b1e3aa0233bd4af0a8dfb0fbfc8ebe05562b44d84ecb7c74581'),
    ('toolbox/FilesPage.qml', 11640, 'fd34d837b5790b950a41e86fc5cd23b4dd8458932379b59f37e4a42474939865'),
    ('toolbox/Label.qml', 270, '7a6d83a7ee45b450db32db224ac372e7d4fbdba57553a71c7230a02e77674376'),
    ('toolbox/MtaEmbedded.qml', 6544, '5c3fe62973da460bebd779f3c15ca2d9906f8ee52513e7fe4a4cb3b1d8982b89'),
    ('toolbox/NativeIcon.qml', 2000, '59ff989674ff862f661e2e8ccdf804eeda0e27cfbd229729219e92141d7d0b1d'),
    ('toolbox/Theme.js', 245, '792bd479b18abb45cd3a71ac8e393ec32064755ffdb605e098691e77681b31ad'),
    ('toolbox/VideoPane.qml', 706, '2e076a699b1dae83b316130db6f0df2ec69025d25ddcdd6dee78ddc438b7b230'),
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
    """Only the pinned helper's two pure definition nodes, not its module/build."""
    require((len(helper_raw), digest(helper_raw)) == HELPER_PIN, 'helper_pin')
    tree = ast.parse(helper_raw.decode('utf-8'), feature_version=(3, 5))
    wanted = ('require', 'enumerate_qrc')
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
    scope = dict(__name__='sender_filecenter_fixed_patch', struct=struct, zlib=zlib, re=re,
                 QRC_OFFSETS=QRC_OFFSETS, NAV_OFFSET=NAV_OFFSET, NAV_SLOT=NAV_SLOT)
    subset = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(subset, str(HELPER), 'exec'), scope)
    require('build' not in scope and '__main__' not in scope, 'old_builder_executed')
    return scope['enumerate_qrc']



def patch_factory_ui(original, remote, enumerate_resources):
    """One original QRC slot, with a fixed explicit original-keyboard reference."""
    resources = enumerate_resources(original)
    require('/NaviPanel.qml' in resources and '/main.qml' in resources, 'factory_roots')
    target = resources['/NaviPanel.qml']
    require(target['flags'] & 1 and target['offset'] == NAV_OFFSET and target['size'] == NAV_SLOT,
            'factory_nav_slot')
    main = resources['/main.qml']['body']
    for pattern in (rb'onSceneSourceChanged\s*:', rb'inner\s*\.\s*visible\s*=\s*false\b',
                    rb'scene\s*\.\s*parent\s*=\s*main\b',
                    rb'scene\s*\.\s*anchors\s*\.\s*fill\s*=\s*main\b',
                    rb'NaviPanel\s*\{\s*id:\s*naviPanel\b',
                    rb'ZybKeyBoard\s*\{\s*id:\s*vk\b'):
        require(re.search(pattern, main) is not None, 'factory_scene_context')
    source = target['body'].decode('utf-8')
    compact = ''.join(line.lstrip(' \t') for line in source.splitlines(keepends=True))
    require(compact.count('id: navi\n') == 1, 'factory_nav_root')
    loader = ('Loader { source: "file://' + remote +
              '/Bridge.qml";onLoaded:{item.navigator=navi;item.factoryKeyboard=vk} }\n')
    qml = compact.replace('id: navi\n', 'id: navi\n' + loader, 1).encode('utf-8')
    packed = struct.pack('>I', len(qml)) + zlib.compress(qml, 9)
    require(0 < len(packed) <= NAV_SLOT, 'nav_compressed_slot')
    require(zlib.decompress(packed[4:]) == qml, 'nav_compressed_readback')
    end = NAV_OFFSET + 4 + NAV_SLOT
    candidate = original[:NAV_OFFSET] + struct.pack('>I', len(packed)) + packed + bytes(NAV_SLOT - len(packed)) + original[end:]
    require(len(candidate) == len(original) and candidate[:NAV_OFFSET] == original[:NAV_OFFSET] and
            candidate[end:] == original[end:], 'elf_outside_slot')
    readback = enumerate_resources(candidate)
    require(set(readback) == set(resources) and readback['/NaviPanel.qml']['body'] == qml and
            sum(readback[path] == value for path, value in resources.items() if path != '/NaviPanel.qml') == 399,
            'factory_resource_readback')
    return candidate, qml, len(packed)

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
        inputs.append(dict(path='candidate/formal-send-filecenter-ui-v5/device/' + name, bytes=size, sha256=sha))
    require(sum(len(raw) for raw in files.values()) + len(bridge) <= SOURCE_BUDGET, 'source_text_budget')
    source_inventory()
    session = secrets.token_hex(12)
    require(re.fullmatch(r'[0-9a-f]{24}', session) is not None, 'fresh_session')
    remote = REMOTE_ROOT + '/' + session
    enumerate_resources = load_algorithms(helper)
    candidate, nav, used = patch_factory_ui(original, remote, enumerate_resources)
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
    require(len(stage_pins) == 19 and sum(row[1] for row in stage_pins) <= 4 * 1024 * 1024,
            'stage_budget')
    out = OUTPUT / ('mta-ui-send-v5-' + session)
    out.mkdir(exist_ok=False)
    (out / 'mta').mkdir(exist_ok=False)
    (out / 'toolbox').mkdir(exist_ok=False)
    for name, raw in sorted(stage_files.items()):
        write_new(out / name, raw)
    # These three PC diagnostics are not staged and must fail target inventory if copied.
    write_new(out / 'NaviPanel.embedded.qml', nav)
    stage = dict(schema='p011-formal-send-filecenter-ui-v5-stage', session=session, remote=remote,
        payload_file_count=18, staged_file_count=19,
        source_manifest=dict(path='SOURCE.sha256', bytes=len(source), sha256=digest(source),
                             format='sha256 space decimal-bytes space relative-path LF'),
        directories=[dict(path=name, mode='0700') for name in STAGE_DIRECTORIES],
        files=[dict(path=name, bytes=size, sha256=sha,
                    mode='0500' if name == 'Z03.mta-ui-candidate' else '0400') for name, size, sha in stage_pins],
        excluded_pc_files=['NaviPanel.embedded.qml', 'stage-manifest.json', 'build-result.json'],
        credentials_in_stage=False, font_files_bundled=False,
        sender_default_tab=True, independent_receiver_entry_required=True)
    write_new(out / 'stage-manifest.json', (json.dumps(stage, indent=2, sort_keys=True) + '\n').encode('ascii'))
    result = dict(schema='p011-formal-send-filecenter-ui-v5-pc-build', evidence_level='PC_BUILD_ONLY',
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
        reused_helper_definitions=['require', 'enumerate_qrc'], old_builder_invoked=False,
        factory_keyboard_reference='original vk supplied explicitly by fixed NaviPanel Loader',
        factory_keyboard_lifecycle='same original visible saved; sceneSource leave or Bridge destruction restores',
        factory_keyboard_runtime_verified=False, original_entry_unchanged=True,
        inputs=inputs + [dict(path='candidate/formal-send-filecenter-ui-v5/entry/Bridge.qml',
                             bytes=BRIDGE_PIN[0], sha256=BRIDGE_PIN[1])],
        builder_sha256=digest(Path(__file__).read_bytes()),
        geometry='parent-owned 800x268; no additional offset or rotation',
        credentials_policy=dict(runtime_basename='credentials.json',
            runtime_fields=['session', 'endpoint', 'token', 'toolboxEndpoint', 'toolboxToken'],
            runtime_file_created=False, included_in_SOURCE=False, included_in_public_logs_or_ZIP=False),
        original_files_changed=False, startup_changed=False, device_tested=False,
        qml_runtime_verified=False, native_component_verified=False, companion_connected=False,
        receive_tested=False, send_tested=False, radio_admission_issued=False,
        phone_interop_verified=False, stock_restoration_verified=False,
        sender_default_tab=True, independent_receiver_entry_required=True,
        docker_invoked=False, sdk_invoked=False)
    write_new(out / 'build-result.json', (json.dumps(result, indent=2, sort_keys=True) + '\n').encode('ascii'))
    print(json.dumps(result, indent=2, sort_keys=True))
    print('BUNDLE=' + str(out))
    return out


if __name__ == '__main__':
    build()
