"""PC-only immutable Receiver plus attached FileCenter GUI builder.

Sixteen fixed UI sources plus the original VK Bridge create eighteen payload files
and SOURCE.sha256 in a fresh exclusive bundle. Only pinned pure definitions are
selected from the reviewed sender-v5 builder; its build/main is never executed.
The original ELF, helper sources, old assets and production graph are read only.
No Qt/SDK/Docker process, runtime validator, credentials, Owner or RF is started.
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
ALGORITHMS = BASE / 'host/build_formal_send_filecenter_ui_v5.py'
ALGORITHMS_PIN = (18604, '6c97c44dd54059eb3b78150bfb2a033aa0a9e8273e900d748df2a0ebca829f49')
HELPER = BASE / 'host/build_formal_ui_candidate_v1.py'
HELPER_PIN = (11889, '5215ebff474016262900c0599355bfa9b6e48e5960ed0a20f07f17428f87e70c')
SOURCE_ROOT = BASE / 'candidate/formal-receive-filecenter-ui-v1/device'
BRIDGE_RELATIVE = 'candidate/formal-send-filecenter-ui-v5/entry/Bridge.qml'
BRIDGE = BASE / BRIDGE_RELATIVE
BRIDGE_PIN = (2514, '1565b10e40a6d44025e662f0a5c6a0695d95e2545026e48f70e319a120dfc134')
OUTPUT = BASE / 'out'
REMOTE_ROOT = '/mnt/data/p011-toolbox/mta-ui'
QRC_OFFSETS = (0x1a3acc, 0x1a5efc, 0x1a9f54)
NAV_OFFSET = 1946708
NAV_SLOT = 1580
SOURCE_BUDGET = 262144
NEW_NAMES = (
    'FormalEntry.qml',
    'ReceiveComposition.qml',
    'mta/MtaHost.qml',
    'mta/MtaPage.qml',
    'toolbox/ExtensionPage.qml',
    'toolbox/FilesPage.qml',
    'toolbox/MtaEmbedded.qml',
    'toolbox/VideoPane.qml',
)
SOURCE_PINS = (
    ('FormalEntry.qml', 'candidate/formal-receive-filecenter-ui-v1/device/FormalEntry.qml', 4102, '58a1fdbf12c696f9d5e5ea02f274eb08d28b7b950cd7a70b37e2a65dcecce4f5'),
    ('ReceiveComposition.qml', 'candidate/formal-receive-filecenter-ui-v1/device/ReceiveComposition.qml', 420, 'ea295bccae4dd3ad4afa3110acbea158da10c9febe2290fc809e8e0fe3b84c66'),
    ('mta/MtaHost.qml', 'candidate/formal-receive-filecenter-ui-v1/device/mta/MtaHost.qml', 1683, 'd7c336fd5aa5803d394685d1c33ad66deb1afa4de2c6e75f1ddf1632f27e66e4'),
    ('mta/MtaPage.qml', 'candidate/formal-receive-filecenter-ui-v1/device/mta/MtaPage.qml', 27441, '6f87bdfc8e3b00a85642dd849963219962c47b563d71bf65c291d1e73bcb77b2'),
    ('toolbox/ExtensionPage.qml', 'candidate/formal-receive-filecenter-ui-v1/device/toolbox/ExtensionPage.qml', 9955, '3647a4070d68e9ce5918a40432e05a075a9dfbf8c9ebf99599d3c4cb5ee27bbc'),
    ('toolbox/FilesPage.qml', 'candidate/formal-receive-filecenter-ui-v1/device/toolbox/FilesPage.qml', 11706, 'abf8b396df1b01765530d17a3b17ab8401a8ea1c5a82a5e72e532517c41c92b0'),
    ('toolbox/MtaEmbedded.qml', 'candidate/formal-receive-filecenter-ui-v1/device/toolbox/MtaEmbedded.qml', 6805, '2c5e508d2b2f31f872089061596092993ee0d0cc4794983abc73fec3396a6565'),
    ('toolbox/VideoPane.qml', 'candidate/formal-receive-filecenter-ui-v1/device/toolbox/VideoPane.qml', 736, 'd83b52d208d53565519ec5a6af067dbcacfeabc6a3fb216d6cc4e9e7df102210'),
    ('mta/MtaButton.qml', 'candidate/formal-send-filecenter-ui-v5/device/mta/MtaButton.qml', 758, '7e1d4e378b8e3293e617f4dc432cce3c70ae7fe377f2ea26950aa9bb11393bff'),
    ('mta/MtaKeyboard.qml', 'candidate/formal-send-filecenter-ui-v5/device/mta/MtaKeyboard.qml', 5345, '2de31e8cde68ab6ff76f4da85c386d5cddb466cccefb809987dddfce2f8c40cc'),
    ('mta/MtaLabel.qml', 'candidate/formal-send-filecenter-ui-v5/device/mta/MtaLabel.qml', 352, '77caf248c2f83ed50f5221082084e5af360d08fc917df98eb84449e24903bd75'),
    ('mta/MtaTheme.js', 'candidate/formal-send-filecenter-ui-v5/device/mta/MtaTheme.js', 262, '5848aa8bf1dab57cfe590dd80da1122eb819c75c1f208f69ad4184bf669a99ff'),
    ('toolbox/Button.qml', 'candidate/formal-send-filecenter-ui-v5/device/toolbox/Button.qml', 666, 'bc8878dfd7c50512934bb9a9a0aab2e54ed84ac86967d3db49d38cd87f3b6216'),
    ('toolbox/Label.qml', 'candidate/formal-send-filecenter-ui-v5/device/toolbox/Label.qml', 270, '7a6d83a7ee45b450db32db224ac372e7d4fbdba57553a71c7230a02e77674376'),
    ('toolbox/NativeIcon.qml', 'candidate/formal-send-filecenter-ui-v5/device/toolbox/NativeIcon.qml', 2000, '59ff989674ff862f661e2e8ccdf804eeda0e27cfbd229729219e92141d7d0b1d'),
    ('toolbox/Theme.js', 'candidate/formal-send-filecenter-ui-v5/device/toolbox/Theme.js', 245, '792bd479b18abb45cd3a71ac8e393ec32064755ffdb605e098691e77681b31ad'),
)
STAGE_DIRECTORIES = ('', 'mta', 'toolbox')


def require(value, code):
    if value is not True: raise ValueError(code)


def algorithm_source():
    """Bootstrap a fixed pin before selecting any old function definitions."""
    def metadata(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    for node in reversed((ALGORITHMS.parent,) + tuple(ALGORITHMS.parent.parents)):
        value = node.lstat()
        require(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
                not getattr(value, 'st_file_attributes', 0) & 0x400, 'algorithm_directory')
    value = ALGORITHMS.lstat()
    require(stat.S_ISREG(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
            not getattr(value, 'st_file_attributes', 0) & 0x400 and
            value.st_size == ALGORITHMS_PIN[0], 'algorithm_file')
    before = metadata(value)
    with ALGORITHMS.open('rb') as stream:
        opened = metadata(os.fstat(stream.fileno()))
        require(opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                opened[3:6] == before[3:6], 'algorithm_open_identity')
        raw = stream.read(ALGORITHMS_PIN[0] + 1)
        require(metadata(os.fstat(stream.fileno())) == opened, 'algorithm_changed')
    require(metadata(ALGORITHMS.lstat()) == before and len(raw) == ALGORITHMS_PIN[0] and
            hashlib.sha256(raw).hexdigest() == ALGORITHMS_PIN[1], 'algorithm_pin')
    return raw


def pure_algorithms(raw):
    """Compile only reviewed pure definitions, never imports/constants/build."""
    require((len(raw), hashlib.sha256(raw).hexdigest()) == ALGORITHMS_PIN, 'algorithm_pin')
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    wanted = ('require', 'digest', 'metadata', 'directory', 'read_pinned', 'relative_name',
              'load_algorithms', 'patch_factory_ui', 'render_template', 'write_new')
    nodes = []
    for name in wanted:
        matches = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
        require(len(matches) == 1 and not matches[0].decorator_list, 'algorithm_definition')
        nodes.append(matches[0])
    scope = dict(__name__='fixed_receive_filecenter_ui_algorithms', ast=ast, hashlib=hashlib, os=os,
                 Path=Path, PurePosixPath=PurePosixPath, re=re, stat=stat, struct=struct,
                 zlib=zlib, HELPER=HELPER, HELPER_PIN=HELPER_PIN, QRC_OFFSETS=QRC_OFFSETS,
                 NAV_OFFSET=NAV_OFFSET, NAV_SLOT=NAV_SLOT)
    subset = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(subset, str(ALGORITHMS), 'exec'), scope)
    require('build' not in scope and 'source_inventory' not in scope, 'old_builder_executed')
    return scope


def source_inventory(directory):
    """Only eight new sources/three directories; eight reused sources pinned separately."""
    expected = set(NEW_NAMES)
    directory(SOURCE_ROOT)
    found = set()
    for relative in STAGE_DIRECTORIES:
        root = SOURCE_ROOT if relative == '' else SOURCE_ROOT / relative
        directory(root)
        with os.scandir(root) as names:
            for count, entry in enumerate(names):
                require(count < 16, 'source_inventory_budget')
                value = entry.stat(follow_symlinks=False)
                require(not stat.S_ISLNK(value.st_mode) and
                        not getattr(value, 'st_file_attributes', 0) & 0x400, 'source_inventory_link')
                name = entry.name if relative == '' else relative + '/' + entry.name
                if name in ('mta', 'toolbox'):
                    require(relative == '' and stat.S_ISDIR(value.st_mode), 'source_inventory_directory')
                else:
                    require(stat.S_ISREG(value.st_mode) and name in expected and name not in found,
                            'source_inventory_extra')
                    found.add(name)
    require(found == expected, 'source_inventory_incomplete')


def build():
    require(sys.platform == 'win32' and os.name == 'nt', 'development_pc_only')
    require(len(sys.argv) == 1, 'fixed_builder_no_arguments')
    require(BASE == Path(r'D:\project\P011\working\MtaP011-v0.1') and
            OUTPUT.is_dir() and OUTPUT.resolve() == OUTPUT, 'fixed_workspace')
    algorithms_raw = algorithm_source()
    fn = pure_algorithms(algorithms_raw)
    read, digest, directory, write = (fn[name] for name in ('read_pinned', 'digest', 'directory', 'write_new'))
    directory(OUTPUT)
    source_inventory(directory)
    require(len(SOURCE_PINS) == 16 and len(set(row[0] for row in SOURCE_PINS)) == 16 and
            all(fn['relative_name'](row[0]) and fn['relative_name'](row[1]) for row in SOURCE_PINS),
            'source_inventory_contract')
    original = read(ORIGINAL, *ORIGINAL_PIN)
    helper = read(HELPER, *HELPER_PIN)
    bridge = read(BRIDGE, *BRIDGE_PIN)
    files, inputs = {}, []
    for name, relative, size, sha in SOURCE_PINS:
        raw = read(BASE / relative, size, sha)
        require(name.endswith(('.qml', '.js')) and b'\0' not in raw, 'source_text_type')
        raw.decode('utf-8')
        files[name] = raw
        inputs.append(dict(path=relative, bytes=size, sha256=sha))
    require(sum(len(raw) for raw in files.values()) + len(bridge) <= SOURCE_BUDGET, 'source_text_budget')
    session = secrets.token_hex(12)
    require(re.fullmatch(r'[0-9a-f]{24}', session) is not None, 'fresh_session')
    remote = REMOTE_ROOT + '/' + session
    enumerate_resources = fn['load_algorithms'](helper)
    candidate, nav, used = fn['patch_factory_ui'](original, remote, enumerate_resources)
    resources, readback = enumerate_resources(original), enumerate_resources(candidate)
    require(len(resources) == 400 and set(resources) == set(readback) and
            sum(readback[name] == value for name, value in resources.items() if name != '/NaviPanel.qml') == 399,
            'qrc_original_399')
    for name, relative, size, sha in SOURCE_PINS: read(BASE / relative, size, sha)
    require(read(ORIGINAL, *ORIGINAL_PIN) == original and read(HELPER, *HELPER_PIN) == helper and
            read(BRIDGE, *BRIDGE_PIN) == bridge and algorithm_source() == algorithms_raw, 'input_readback')
    source_inventory(directory)
    files['FormalEntry.qml'] = fn['render_template'](files['FormalEntry.qml'], session, remote, True)
    files['Bridge.qml'] = fn['render_template'](bridge, session, remote, False)
    files['Z03.mta-ui-candidate'] = candidate
    require(len(files) == 18 and 'credentials.json' not in files and
            all(fn['relative_name'](name) for name in files) and
            all(re.search(rb'@[A-Z_]+@', raw) is None for name, raw in files.items() if name != 'Z03.mta-ui-candidate'),
            'payload_inventory')
    pins = tuple((name, len(raw), digest(raw)) for name, raw in sorted(files.items()))
    source = ''.join(sha + ' ' + str(size) + ' ' + name + '\n' for name, size, sha in pins).encode('ascii')
    require(len(source) <= 4096 and len(source.splitlines()) == 18, 'source_manifest_budget')
    files['SOURCE.sha256'] = source
    stage_pins = tuple((name, len(raw), digest(raw)) for name, raw in sorted(files.items()))
    require(len(stage_pins) == 19 and sum(row[1] for row in stage_pins) <= 4 * 1024 * 1024, 'stage_budget')
    out = OUTPUT / ('mta-ui-receive-filecenter-v1-' + session)
    out.mkdir(exist_ok=False)
    (out / 'mta').mkdir(exist_ok=False)
    (out / 'toolbox').mkdir(exist_ok=False)
    for name, raw in sorted(files.items()): write(out / name, raw)
    write(out / 'NaviPanel.embedded.qml', nav)
    stage = dict(schema='p011-formal-receive-filecenter-ui-v1-stage', session=session, remote=remote,
        payload_file_count=18, staged_file_count=19,
        source_manifest=dict(path='SOURCE.sha256', bytes=len(source), sha256=digest(source),
                             format='sha256 space decimal-bytes space relative-path LF'),
        directories=[dict(path=name, mode='0700') for name in STAGE_DIRECTORIES],
        files=[dict(path=name, bytes=size, sha256=sha,
                    mode='0500' if name == 'Z03.mta-ui-candidate' else '0400') for name, size, sha in stage_pins],
        excluded_pc_files=['NaviPanel.embedded.qml', 'stage-manifest.json', 'build-result.json'],
        credentials_in_stage=False, font_files_bundled=False, receive_default_tab=True,
        single_mta_owner=True, companion_required=True)
    write(out / 'stage-manifest.json', (json.dumps(stage, indent=2, sort_keys=True) + '\n').encode('ascii'))
    result = dict(schema='p011-formal-receive-filecenter-ui-v1-pc-build', evidence_level='PC_BUILD_ONLY',
        session=session, remote=remote, original_path=ORIGINAL_RELATIVE,
        original_bytes=len(original), original_sha256=ORIGINAL_PIN[1],
        candidate_bytes=len(candidate), candidate_sha256=digest(candidate),
        source_manifest_bytes=len(source), source_manifest_sha256=digest(source),
        source_manifest_files=18, staged_file_count=19, staged_directory_count=3,
        source_ui_files=16, source_qml_files=14, source_js_files=2, bridge_source_files=1,
        changed_resource='/NaviPanel.qml', resources_verified=400, other_resources_original_bytes=399,
        record_offset=NAV_OFFSET, slot_bytes=NAV_SLOT, used_bytes=used,
        elf_total_length_unchanged=True, elf_outside_slot_unchanged=True, compressed_qml_readback=True,
        reused_algorithms_path='host/build_formal_send_filecenter_ui_v5.py',
        reused_algorithms_sha256=ALGORITHMS_PIN[1],
        reused_algorithms_definitions=['require', 'digest', 'metadata', 'directory', 'read_pinned',
            'relative_name', 'load_algorithms', 'patch_factory_ui', 'render_template', 'write_new'],
        reused_helper_path='host/build_formal_ui_candidate_v1.py', reused_helper_sha256=HELPER_PIN[1],
        reused_helper_definitions=['require', 'enumerate_qrc'], old_builder_invoked=False,
        factory_keyboard_reference='original vk supplied explicitly by fixed NaviPanel Loader',
        factory_keyboard_lifecycle='same original visible saved; sceneSource leave or Bridge destruction restores',
        factory_keyboard_runtime_verified=False, original_entry_unchanged=True,
        inputs=inputs + [dict(path=BRIDGE_RELATIVE, bytes=BRIDGE_PIN[0], sha256=BRIDGE_PIN[1])],
        builder_sha256=digest(Path(__file__).read_bytes()),
        geometry='parent-owned 800x268; no additional offset or rotation',
        credentials_policy=dict(runtime_basename='credentials.json', runtime_fields=['session', 'endpoint', 'token', 'toolboxEndpoint', 'toolboxToken'],
            runtime_file_created=False, included_in_SOURCE=False, included_in_public_logs_or_ZIP=False),
        source_inputs_readback_verified=True, original_files_changed=False, startup_changed=False,
        device_tested=False, qml_runtime_verified=False, native_component_verified=False,
        service_owner_connected=False, receive_tested=False, send_tested=False,
        radio_admission_issued=False, phone_interop_verified=False, stock_restoration_verified=False,
        filecenter_service_connected=False, received_directory_opened=False,
        user_media_playback_verified=False, mta_leave_quiescence_verified=False,
        receive_default_tab=True, single_mta_owner=True, companion_required=True,
        docker_invoked=False, sdk_invoked=False)
    write(out / 'build-result.json', (json.dumps(result, indent=2, sort_keys=True) + '\n').encode('ascii'))
    print(json.dumps(result, indent=2, sort_keys=True))
    print('BUNDLE=' + str(out))
    return out


if __name__ == '__main__':
    build()
