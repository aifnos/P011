"""Fixed PC-only navigation GUI source check and explicit exclusive build.

Reuse the frozen Receiver GUI builder's constant/pure-helper definitions only.
Its build/main and all runtime/graph/device entry points are never executed.
Default SOURCE checks pins and exact length budgets without inventing a session
or patching an ELF. --build alone produces a fresh, exclusively created bundle.
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
DONOR = BASE / 'host/build_formal_receive_filecenter_ui_v1.py'
DONOR_PIN = (16372, 'a86df45cec0b15ebac54fc77fe49873bfd701528fa720d6d9f26d2bcf0fe99a3')
SOURCE_ROOT = BASE / 'candidate/formal-receive-filecenter-navigation-gui-v1/device'
OUTPUT_PREFIX = 'mta-ui-receive-filecenter-navigation-gui-v1-'
NAVIGATION_ARGUMENT = '--p011-mta-navigation-qt-test-v1'
NAVIGATION_PINS = (
    ('FormalEntry.qml', 'candidate/formal-receive-filecenter-navigation-gui-v1/device/FormalEntry.qml',
     5696, '41dc132f5a99adf05d6d1a8b363d652d2d4d7968f47d441e402cadbcad8a732a'),
    ('toolbox/FilesPage.qml', 'candidate/formal-receive-filecenter-navigation-gui-v1/device/toolbox/FilesPage.qml',
     11973, '4d4deb4c57a0e90360e2f95b9ee55dfcf43e0cbe464e3441823418a43feff867'),
    ('NavigationTest.qml', 'candidate/formal-receive-filecenter-navigation-gui-v1/device/NavigationTest.qml',
     8731, 'efb77831d309e2deba30f646521be8d747efb8e4e05cfc72d25b8e3da0df2216'),
)
DONOR_CONSTANTS = (
    'BASE', 'PROJECT', 'ORIGINAL_RELATIVE', 'ORIGINAL', 'ORIGINAL_PIN',
    'ALGORITHMS', 'ALGORITHMS_PIN', 'HELPER', 'HELPER_PIN', 'SOURCE_ROOT',
    'BRIDGE_RELATIVE', 'BRIDGE', 'BRIDGE_PIN', 'OUTPUT', 'REMOTE_ROOT',
    'QRC_OFFSETS', 'NAV_OFFSET', 'NAV_SLOT', 'SOURCE_BUDGET', 'NEW_NAMES',
    'SOURCE_PINS', 'STAGE_DIRECTORIES',
)
DONOR_FUNCTIONS = ('require', 'algorithm_source', 'pure_algorithms', 'source_inventory')


def require(value, code):
    if value is not True:
        raise ValueError(code)


def bootstrap_source():
    """Pin the donor's actual bytes before selecting any of its definitions."""
    def identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    for node in reversed((DONOR.parent,) + tuple(DONOR.parent.parents)):
        value = node.lstat()
        require(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
                not getattr(value, 'st_file_attributes', 0) & 0x400, 'donor_directory')
    value = DONOR.lstat()
    require(stat.S_ISREG(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
            not getattr(value, 'st_file_attributes', 0) & 0x400 and
            value.st_size == DONOR_PIN[0], 'donor_file')
    before = identity(value)
    with DONOR.open('rb') as stream:
        opened = identity(os.fstat(stream.fileno()))
        require(opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                opened[3:6] == before[3:6], 'donor_open_identity')
        raw = stream.read(DONOR_PIN[0] + 1)
        require(identity(os.fstat(stream.fileno())) == opened, 'donor_changed')
    require(identity(DONOR.lstat()) == before and
            (len(raw), hashlib.sha256(raw).hexdigest()) == DONOR_PIN, 'donor_pin')
    return raw


def donor_definitions(raw):
    """Only fixed assignments and four pure definitions, not old imports/main."""
    require((len(raw), hashlib.sha256(raw).hexdigest()) == DONOR_PIN, 'donor_pin')
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    nodes, names = [], []
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in DONOR_CONSTANTS:
                require(name not in names, 'donor_constant_duplicate')
                names.append(name)
                nodes.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in DONOR_FUNCTIONS:
            require(node.name not in names and not node.decorator_list, 'donor_function_duplicate')
            names.append(node.name)
            nodes.append(node)
    require(set(names) == set(DONOR_CONSTANTS + DONOR_FUNCTIONS), 'donor_definitions')
    scope = dict(__name__='navigation_fixed_receive_builder_definitions', __file__=str(DONOR),
                 ast=ast, hashlib=hashlib, os=os, Path=Path, PurePosixPath=PurePosixPath,
                 re=re, stat=stat, struct=struct, zlib=zlib)
    subset = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(subset, str(DONOR), 'exec'), scope)
    require('build' not in scope and 'main' not in scope and scope['BASE'] == BASE and
            scope['NAV_SLOT'] == 1580 and scope['SOURCE_BUDGET'] == 262144 and
            scope['STAGE_DIRECTORIES'] == ('', 'mta', 'toolbox'), 'donor_fixed_contract')
    return scope


def navigation_inventory(directory):
    """The new source tree has only three QML and root/toolbox, not stage dirs."""
    expected, found = {row[0] for row in NAVIGATION_PINS}, set()
    require(len(expected) == 3, 'navigation_source_count')
    for relative in ('', 'toolbox'):
        root = SOURCE_ROOT if relative == '' else SOURCE_ROOT / relative
        directory(root)
        with os.scandir(root) as names:
            for count, entry in enumerate(names):
                require(count < 8, 'navigation_inventory_budget')
                value = entry.stat(follow_symlinks=False)
                require(not stat.S_ISLNK(value.st_mode) and
                        not getattr(value, 'st_file_attributes', 0) & 0x400, 'navigation_inventory_link')
                name = entry.name if relative == '' else relative + '/' + entry.name
                if name == 'toolbox':
                    require(relative == '' and stat.S_ISDIR(value.st_mode), 'navigation_inventory_directory')
                else:
                    require(stat.S_ISREG(value.st_mode) and name in expected and name not in found,
                            'navigation_inventory_extra')
                    found.add(name)
    require(found == expected, 'navigation_inventory_incomplete')


def inputs():
    require(sys.platform == 'win32' and os.name == 'nt', 'development_pc_only')
    require(BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'fixed_workspace')
    donor_raw = bootstrap_source()
    donor = donor_definitions(donor_raw)
    algorithm_raw = donor['algorithm_source']()
    fn = donor['pure_algorithms'](algorithm_raw)
    read, directory = fn['read_pinned'], fn['directory']
    require(donor['OUTPUT'].is_dir() and donor['OUTPUT'].resolve() == donor['OUTPUT'], 'fixed_output')
    directory(donor['OUTPUT'])
    donor['source_inventory'](directory)
    navigation_inventory(directory)
    old_pins = donor['SOURCE_PINS']
    require(len(old_pins) == 16 and len({row[0] for row in old_pins}) == 16, 'donor_source_count')
    replacements = {row[0]: row for row in NAVIGATION_PINS[:2]}
    require(set(replacements).issubset({row[0] for row in old_pins}), 'navigation_replacement_names')
    source_pins = tuple(replacements.get(row[0], row) for row in old_pins) + NAVIGATION_PINS[2:]
    require(len(source_pins) == len({row[0] for row in source_pins}) == 17 and
            all(fn['relative_name'](row[0]) and fn['relative_name'](row[1]) for row in source_pins),
            'source_inventory_contract')
    original = read(donor['ORIGINAL'], *donor['ORIGINAL_PIN'])
    helper = read(donor['HELPER'], *donor['HELPER_PIN'])
    bridge = read(donor['BRIDGE'], *donor['BRIDGE_PIN'])
    files = {}
    # Retain/check all sixteen donor inputs, including the two replaced originals.
    for name, relative, size, sha in old_pins:
        read(BASE / relative, size, sha)
    for name, relative, size, sha in source_pins:
        raw = read(BASE / relative, size, sha)
        require(name.endswith(('.qml', '.js')) and b'\0' not in raw, 'source_text_type')
        raw.decode('utf-8')
        files[name] = raw
    require(sum(len(raw) for raw in files.values()) + len(bridge) <= donor['SOURCE_BUDGET'],
            'source_text_budget')
    require(files['FormalEntry.qml'].count(NAVIGATION_ARGUMENT.encode('ascii')) == 1 and
            b'import QtTest 1.2 as Testing' in files['NavigationTest.qml'] and
            b'Testing.TestEvent' in files['NavigationTest.qml'], 'navigation_opt_in_sources')
    planned_sizes = {name: len(raw) for name, raw in files.items()}
    remote_size = len(donor['REMOTE_ROOT'].encode('ascii')) + 1 + 24
    for name, raw, session_required in (('FormalEntry.qml', files['FormalEntry.qml'], True),
                                        ('Bridge.qml', bridge, False)):
        require(raw.count(b'@REMOTE@') == 1 and
                (raw.count(b'@SESSION@') == 1 if session_required else b'@SESSION@' not in raw),
                'template_contract')
        markers = re.findall(rb'@[A-Z_]+@', raw)
        require(sorted(markers) == sorted([b'@REMOTE@', b'@SESSION@'] if session_required else [b'@REMOTE@']),
                'template_unresolved')
        planned_sizes[name] = len(raw) + remote_size - len(b'@REMOTE@')
        if session_required:
            planned_sizes[name] += 24 - len(b'@SESSION@')
    for name, raw in files.items():
        if name != 'FormalEntry.qml':
            require(re.search(rb'@[A-Z_]+@', raw) is None, 'source_unresolved')
    planned_sizes['Z03.mta-ui-candidate'] = len(original)
    require(len(planned_sizes) == 19 and
            {'' if str(PurePosixPath(name).parent) == '.' else str(PurePosixPath(name).parent)
             for name in planned_sizes} == set(donor['STAGE_DIRECTORIES']), 'payload_layout')
    manifest_size = sum(64 + 1 + len(str(size)) + 1 + len(name.encode('ascii')) + 1
                        for name, size in sorted(planned_sizes.items()))
    stage_size = sum(planned_sizes.values()) + manifest_size
    require(manifest_size <= 4096 and stage_size <= 4 * 1024 * 1024, 'planned_stage_budget')
    source_raw = Path(__file__).read_bytes()
    ast.parse(source_raw.decode('utf-8'), feature_version=(3, 5))
    return dict(donor=donor, fn=fn, donor_raw=donor_raw, algorithm_raw=algorithm_raw,
                source_pins=source_pins, files=files, original=original, helper=helper,
                bridge=bridge, source_raw=source_raw, planned_sizes=planned_sizes,
                manifest_size=manifest_size, stage_size=stage_size)


def readback(value):
    donor, fn = value['donor'], value['fn']
    read = fn['read_pinned']
    for name, relative, size, sha in donor['SOURCE_PINS'] + value['source_pins']:
        read(BASE / relative, size, sha)
    require(read(donor['ORIGINAL'], *donor['ORIGINAL_PIN']) == value['original'] and
            read(donor['HELPER'], *donor['HELPER_PIN']) == value['helper'] and
            read(donor['BRIDGE'], *donor['BRIDGE_PIN']) == value['bridge'] and
            donor['algorithm_source']() == value['algorithm_raw'] and
            bootstrap_source() == value['donor_raw'] and
            Path(__file__).read_bytes() == value['source_raw'], 'input_readback')
    donor['source_inventory'](fn['directory'])
    navigation_inventory(fn['directory'])


def source_report(value):
    donor = value['donor']
    return dict(schema='p011-formal-receive-filecenter-navigation-gui-v1-source',
        evidence_level='SOURCE_ONLY', source_ui_files=17, source_qml_files=15, source_js_files=2,
        payload_file_count=19, staged_file_count=20, staged_directory_count=3,
        planned_source_manifest_bytes=value['manifest_size'], planned_stage_bytes=value['stage_size'],
        stage_budget_bytes=4 * 1024 * 1024, source_text_budget_bytes=donor['SOURCE_BUDGET'],
        source_text_bytes=sum(len(raw) for raw in value['files'].values()) + len(value['bridge']),
        template_size_only=True, session_created=False, bundle_created=False, elf_patched=False,
        donor_path=str(DONOR.relative_to(BASE)), donor_bytes=DONOR_PIN[0], donor_sha256=DONOR_PIN[1],
        donor_selected_constants=list(DONOR_CONSTANTS), donor_selected_definitions=list(DONOR_FUNCTIONS),
        donor_build_executed=False, sender_build_executed=False, old_suite_executed=False,
        builder_bytes=len(value['source_raw']), builder_sha256=hashlib.sha256(value['source_raw']).hexdigest(),
        source_pins=[dict(path=relative, bytes=size, sha256=sha) for name, relative, size, sha in value['source_pins']],
        navigation_argument=NAVIGATION_ARGUMENT, navigation_argument_connected=False,
        validator_connected=False, worker_connected=False, graph_changed=False,
        qml_runtime_verified=False, qt_test_component_verified=False, navigation_device_verified=False,
        credentials_created=False, fonts_bundled=False, rotation_added=False,
        device_executed=False, radio_executed=False, sdk_invoked=False, docker_invoked=False)


def build(value):
    donor, fn = value['donor'], value['fn']
    files = value['files'].copy()
    digest, write = fn['digest'], fn['write_new']
    session = secrets.token_hex(12)
    require(re.fullmatch(r'[0-9a-f]{24}', session) is not None, 'fresh_session')
    require(not any(node.name.endswith('-' + session) for node in donor['OUTPUT'].iterdir()), 'session_already_exists')
    remote = donor['REMOTE_ROOT'] + '/' + session
    enumerate_resources = fn['load_algorithms'](value['helper'])
    candidate, nav, used = fn['patch_factory_ui'](value['original'], remote, enumerate_resources)
    resources, patched = enumerate_resources(value['original']), enumerate_resources(candidate)
    end = donor['NAV_OFFSET'] + 4 + donor['NAV_SLOT']
    require(len(candidate) == len(value['original']) and candidate[:donor['NAV_OFFSET']] == value['original'][:donor['NAV_OFFSET']] and
            candidate[end:] == value['original'][end:] and 0 < used <= donor['NAV_SLOT'], 'elf_same_slot')
    require(len(resources) == 400 and set(resources) == set(patched) and
            sum(patched[name] == raw for name, raw in resources.items() if name != '/NaviPanel.qml') == 399,
            'qrc_original_399')
    readback(value)
    files['FormalEntry.qml'] = fn['render_template'](files['FormalEntry.qml'], session, remote, True)
    files['Bridge.qml'] = fn['render_template'](value['bridge'], session, remote, False)
    files['Z03.mta-ui-candidate'] = candidate
    require(len(files) == 19 and 'credentials.json' not in files and
            {name: len(raw) for name, raw in files.items()} == value['planned_sizes'] and
            all(fn['relative_name'](name) for name in files) and
            all(re.search(rb'@[A-Z_]+@', raw) is None for name, raw in files.items() if name != 'Z03.mta-ui-candidate'),
            'payload_inventory')
    pins = tuple((name, len(raw), digest(raw)) for name, raw in sorted(files.items()))
    source = ''.join(sha + ' ' + str(size) + ' ' + name + '\n' for name, size, sha in pins).encode('ascii')
    require(len(source) == value['manifest_size'] and len(source) <= 4096 and len(source.splitlines()) == 19,
            'source_manifest_budget')
    files['SOURCE.sha256'] = source
    stage_pins = tuple((name, len(raw), digest(raw)) for name, raw in sorted(files.items()))
    require(len(stage_pins) == 20 and sum(row[1] for row in stage_pins) == value['stage_size'] and
            sum(row[1] for row in stage_pins) <= 4 * 1024 * 1024, 'stage_budget')
    out = donor['OUTPUT'] / (OUTPUT_PREFIX + session)
    out.mkdir(exist_ok=False)
    (out / 'mta').mkdir(exist_ok=False)
    (out / 'toolbox').mkdir(exist_ok=False)
    for name, raw in sorted(files.items()):
        write(out / name, raw)
    write(out / 'NaviPanel.embedded.qml', nav)
    stage = dict(schema='p011-formal-receive-filecenter-navigation-gui-v1-stage', session=session, remote=remote,
        payload_file_count=19, staged_file_count=20,
        source_manifest=dict(path='SOURCE.sha256', bytes=len(source), sha256=digest(source),
                             format='sha256 space decimal-bytes space relative-path LF'),
        directories=[dict(path=name, mode='0700') for name in donor['STAGE_DIRECTORIES']],
        files=[dict(path=name, bytes=size, sha256=sha,
                    mode='0500' if name == 'Z03.mta-ui-candidate' else '0400') for name, size, sha in stage_pins],
        excluded_pc_files=['NaviPanel.embedded.qml', 'stage-manifest.json', 'build-result.json'],
        credentials_in_stage=False, font_files_bundled=False, receive_default_tab=True,
        single_mta_owner=True, companion_required=True, navigation_argument=NAVIGATION_ARGUMENT,
        navigation_argument_connected=False, navigation_runtime_verified=False)
    write(out / 'stage-manifest.json', (json.dumps(stage, indent=2, sort_keys=True) + '\n').encode('ascii'))
    result = source_report(value)
    result.update(schema='p011-formal-receive-filecenter-navigation-gui-v1-pc-build', evidence_level='PC_BUILD_ONLY',
        template_size_only=False, session_created=True, bundle_created=True, elf_patched=True,
        session=session, remote=remote, bundle=str(out),
        original_path=donor['ORIGINAL_RELATIVE'], original_bytes=len(value['original']), original_sha256=donor['ORIGINAL_PIN'][1],
        candidate_bytes=len(candidate), candidate_sha256=digest(candidate),
        source_manifest_bytes=len(source), source_manifest_sha256=digest(source),
        resources_verified=400, other_resources_original_bytes=399, changed_resource='/NaviPanel.qml',
        record_offset=donor['NAV_OFFSET'], slot_bytes=donor['NAV_SLOT'], used_bytes=used,
        elf_total_length_unchanged=True, elf_outside_slot_unchanged=True, compressed_qml_readback=True,
        source_inputs_readback_verified=True, original_files_changed=False, startup_changed=False,
        reused_algorithms_path='host/build_formal_send_filecenter_ui_v5.py', reused_algorithms_sha256=donor['ALGORITHMS_PIN'][1],
        reused_helper_path='host/build_formal_ui_candidate_v1.py', reused_helper_sha256=donor['HELPER_PIN'][1],
        bridge_bytes=donor['BRIDGE_PIN'][0], bridge_sha256=donor['BRIDGE_PIN'][1],
        factory_keyboard_reference='original vk supplied explicitly by fixed NaviPanel Loader',
        factory_keyboard_lifecycle='same original visible saved; sceneSource leave or Bridge destruction restores',
        factory_keyboard_runtime_verified=False, original_entry_unchanged=True,
        geometry='parent-owned 800x268; no additional offset or rotation',
        credentials_policy=dict(runtime_basename='credentials.json',
            runtime_fields=['session', 'endpoint', 'token', 'toolboxEndpoint', 'toolboxToken'],
            runtime_file_created=False, included_in_SOURCE=False, included_in_public_logs_or_ZIP=False),
        service_owner_connected=False, receive_tested=False, send_tested=False, radio_admission_issued=False,
        phone_interop_verified=False, stock_restoration_verified=False, received_directory_opened=False,
        user_media_playback_verified=False, mta_leave_quiescence_verified=False)
    write(out / 'build-result.json', (json.dumps(result, indent=2, sort_keys=True) + '\n').encode('ascii'))
    print(json.dumps(result, indent=2, sort_keys=True))
    print('BUNDLE=' + str(out))


def main():
    require(sys.argv[1:] in ([], ['--build']), 'fixed_source_or_pc_build_only')
    value = inputs()
    if sys.argv[1:] == ['--build']:
        build(value)
    else:
        readback(value)
        print(json.dumps(source_report(value), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
