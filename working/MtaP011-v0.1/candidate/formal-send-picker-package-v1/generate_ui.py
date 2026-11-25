"""PC-only immutable package of the already-tested sender picker correction.

Default SOURCE performs only bounded, pinned reads and in-memory byte/AST/QRC
proofs. Only an explicit --write may exclusively create this fixed new bundle,
validator, guardian and generation report. It never runs an old builder/main,
Qt fixture, validator, guardian, Worker, ADB, service, RF or device operation.
Only authenticated pure QRC definitions are selected by AST. Old inputs and
any partial exclusive outputs are retained; no overwrite, cleanup or retry.
The Worker/HOST/ordinary sender graph is a separate root-owned integration.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import zlib


BASE = Path(__file__).resolve().parents[2]
ROOT = 'candidate/formal-send-picker-package-v1'
PROJECT = BASE.parents[1]
SESSION = 'c69296a193ff43ce8e5b901d'
OLD_SESSION = 'a44b98dd639095d9063c9e1a'
REMOTE_ROOT = '/mnt/data/p011-toolbox/mta-ui'
REMOTE = REMOTE_ROOT + '/' + SESSION
OLD_REMOTE = REMOTE_ROOT + '/' + OLD_SESSION
CONTROL_SUFFIX = '-formal-send-picker-package-v1'
CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + CONTROL_SUFFIX
CONTROL = '/var/volatile/tmp/' + CONTROL_NAME
BUNDLE = 'out/mta-ui-send-picker-v1-' + SESSION
OLD_BUNDLE = 'out/mta-ui-send-v5-' + OLD_SESSION
VALIDATOR = ROOT + '/runtime/ui_assets.py'
GUARDIAN = ROOT + '/runtime/ui_guardian.py'
GENERATION = ROOT + '/generation.json'
SELF = ROOT + '/generate_ui.py'
ORIGINAL_PATH = '06_Firmware/backups/v2.4.0-20260923-162730/files/Z03'
ORIGINAL_PIN = (4103844, 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a')
BUILDER = ('host/build_formal_send_filecenter_ui_v5.py', 18604,
           '6c97c44dd54059eb3b78150bfb2a033aa0a9e8273e900d748df2a0ebca829f49')
QRC_HELPER = ('host/build_formal_ui_candidate_v1.py', 11889,
              '5215ebff474016262900c0599355bfa9b6e48e5960ed0a20f07f17428f87e70c')
OLD_VALIDATOR = ('candidate/formal-send-filecenter-ui-v5/runtime/ui_assets.py', 12526,
                 'ac6bffe961034558da8be607d74bc4edb62209b23ce80b8a930138a8fc7eb890')
OLD_GUARDIAN = ('candidate/formal-send-filecenter-ui-v7/runtime/ui_guardian.py', 43993,
                '30b7157cabf3dd75eb82a671a343a106c1f9e688c1ad60e12c7b8e172ffc255e')
OLD_STAGE = (OLD_BUNDLE + '/stage-manifest.json', 4227,
             '80eaec304c785b5fa267f5ae2be49790413293fa49ec392420f8ef18a641f270')
OLD_BUILD = (OLD_BUNDLE + '/build-result.json', 6009,
             '92d940049426d547d8c978c1076c46cca9e88b345214f2f1e41df1d73f6f26f3')
OLD_NAV = (OLD_BUNDLE + '/NaviPanel.embedded.qml', 6055,
           '50dbab35c6a5a842a63bd4744e9aa88a3745eaea9db8b4c650a204702f8a669a')
PICKER = ('candidate/formal-send-picker-generation-v1/device/mta/MtaHost.qml', 6602,
          'dcb6178f6d3179b7bab61e6818ae21a02443c902446f6b203c82bd16b8b479c3')
PICKER_MOTHER = ('candidate/formal-send-filecenter-ui-v5/device/mta/MtaHost.qml', 6342,
                 'c151b0bd7a9b686f5110eef968c50506d9a814c14b5d9db9ccebfe8f05d7b322')
PICKER_DELTA = ('candidate/formal-send-picker-generation-v1/exactsource-delta.json', 1840,
                'cf3e8d6146b95cb6c27e941230d8eaa80fe0fd96a4cb8baf32f724f1bafa2b7e')
QT_RESULT = ('results/receive-durable-picker-v1-host-20261006-000545-54ec793c/result.json', 3846,
             'f4762f52a23b1eb5a03484ad1ee1dcac50986425f17a19a37aba7f3846f8d021')
QT_TEST = ('tests/test_formal_send_picker_generation_v1.py', 8905,
           '6a378b14edbca81ac84f99738908ce25759c1905a8ed572f7749bd5bd1dee367')
QT_FIXTURE = ('tests/qml_candidate_fixture_v1.py', 7249,
              '346c11f2a432101d0bc0cc40c8bcccb5b50c2f39eba4a396a291f5f5949fecd3')
INPUT_PINS = (BUILDER, QRC_HELPER, OLD_VALIDATOR, OLD_GUARDIAN, OLD_STAGE,
              OLD_BUILD, OLD_NAV, PICKER, PICKER_MOTHER, PICKER_DELTA,
              QT_RESULT, QT_TEST, QT_FIXTURE)
QRC_OFFSETS = (0x1a3acc, 0x1a5efc, 0x1a9f54)
NAV_OFFSET = 1946708
NAV_SLOT = 1580
SOURCE_BUDGET = 262144
STAGE_BUDGET = 4 * 1024 * 1024
FILE_BUDGET = 5 * 1024 * 1024
STAGE_DIRECTORIES = ('', 'mta', 'toolbox')
PC_NAMES = ('NaviPanel.embedded.qml', 'stage-manifest.json', 'build-result.json')
PAYLOAD_CHANGED = ('Bridge.qml', 'FormalEntry.qml', 'Z03.mta-ui-candidate', 'mta/MtaHost.qml')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, raw):
    return (path, len(raw), digest(raw))


def json_raw(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def meta(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def safe_directory(path):
    for node in reversed((path,) + tuple(path.parents)):
        value = node.lstat()
        need(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
             not getattr(value, 'st_file_attributes', 0) & 0x400, 'directory_link_or_type')
    return meta(path.lstat())


def relative(path):
    return (type(path) is str and re.fullmatch(r'[A-Za-z0-9_./-]{1,160}', path) is not None and
            not path.startswith('/') and '\\' not in path and
            all(part not in ('', '.', '..') for part in path.split('/')))


def scoped(path):
    need(relative(path), 'relative_path')
    return BASE / path


def read_pinned(path, expected):
    length, sha = expected
    need(type(length) is int and 0 < length <= FILE_BUDGET and type(sha) is str and
         re.fullmatch(r'[0-9a-f]{64}', sha) is not None, 'input_pin')
    safe_directory(path.parent)
    value = path.lstat()
    need(stat.S_ISREG(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
         not getattr(value, 'st_file_attributes', 0) & 0x400 and value.st_nlink == 1 and
         value.st_size == length, 'input_metadata')
    before = meta(value)
    with path.open('rb') as stream:
        opened = meta(os.fstat(stream.fileno()))
        same = opened[:4] == before[:4] and opened[4:6] == before[4:6] if os.name == 'nt' else opened == before
        need(same, 'input_open_identity')
        raw = stream.read(length + 1)
        need(meta(os.fstat(stream.fileno())) == opened, 'input_changed_during_read')
    need(meta(path.lstat()) == before and (len(raw), digest(raw)) == expected, 'input_readback_pin')
    return raw


def assignments(raw):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    rows = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            need(name not in rows, 'duplicate_assignment')
            rows[name] = node
    return tree, rows


def span(raw, node):
    lines = raw.splitlines(keepends=True)
    return (sum(map(len, lines[:node.lineno - 1])) + node.col_offset,
            sum(map(len, lines[:node.end_lineno - 1])) + node.end_col_offset)


def node_bytes(raw, node):
    begin, end = span(raw, node)
    return raw[begin:end]


def constant_overlay(raw, expressions, label):
    """Only named whole assignments; exact inverse and every definition line kept."""
    before_tree, before_rows = assignments(raw)
    need(set(expressions).issubset(before_rows), label + '_assignment_missing')
    edits, proof = [], []
    for name, expression in expressions.items():
        node = before_rows[name]
        old = node_bytes(raw, node)
        new = (name + ' = ' + expression).encode('ascii')
        need(old != new and old.count(b'\n') == new.count(b'\n') and raw.count(old) == 1,
             label + '_assignment_delta')
        begin, end = span(raw, node)
        edits.append((begin, end, old, new))
        proof.append(dict(name=name, before=old.decode('utf-8'), after=new.decode('ascii')))
    after = raw
    for begin, end, old, new in sorted(edits, reverse=True):
        need(after[begin:end] == old, label + '_forward_span')
        after = after[:begin] + new + after[end:]
    after_tree, after_rows = assignments(after)
    reverse = after
    for row in reversed(proof):
        old, new = row['before'].encode('utf-8'), row['after'].encode('ascii')
        need(reverse.count(new) == 1, label + '_inverse_unique')
        reverse = reverse.replace(new, old, 1)
    need(reverse == raw and ast.dump(ast.parse(reverse, feature_version=(3, 5)), include_attributes=True) ==
         ast.dump(before_tree, include_attributes=True), label + '_complete_inverse')
    need(len(before_tree.body) == len(after_tree.body) and set(before_rows) == set(after_rows),
         label + '_body_inventory')
    for left, right in zip(before_tree.body, after_tree.body):
        changed = isinstance(left, ast.Assign) and len(left.targets) == 1 and isinstance(left.targets[0], ast.Name) and left.targets[0].id in expressions
        if changed:
            need(isinstance(right, ast.Assign) and node_bytes(after, right) ==
                 (left.targets[0].id + ' = ' + expressions[left.targets[0].id]).encode('ascii') and
                 left.lineno == right.lineno and left.end_lineno == right.end_lineno,
                 label + '_changed_assignment')
        else:
            need(ast.dump(left, include_attributes=False) == ast.dump(right, include_attributes=False) and
                 node_bytes(raw, left) == node_bytes(after, right) and left.lineno == right.lineno and
                 left.end_lineno == right.end_lineno, label + '_nonassignment_or_definition_changed')
    return after, proof


def literal(raw, name):
    unused, rows = assignments(raw)
    need(name in rows, 'literal_missing')
    return ast.literal_eval(rows[name].value)


def pure_qrc(inputs):
    """No old import/main/build; only three pinned, fully read pure definitions."""
    scopes = []
    wanted_rows = ((QRC_HELPER, ('require', 'enumerate_qrc')), (BUILDER, ('patch_factory_ui',)))
    scope = dict(__name__='picker_package_qrc_private', struct=struct, zlib=zlib, re=re,
                 QRC_OFFSETS=QRC_OFFSETS, NAV_OFFSET=NAV_OFFSET, NAV_SLOT=NAV_SLOT)
    for source_pin, wanted in wanted_rows:
        raw = inputs[source_pin[0]]
        need(pin(source_pin[0], raw) == source_pin, 'qrc_source_pin')
        tree, constants = assignments(raw)
        need(all(name in constants and ast.literal_eval(constants[name].value) == expected
                 for name, expected in (('QRC_OFFSETS', QRC_OFFSETS), ('NAV_OFFSET', NAV_OFFSET), ('NAV_SLOT', NAV_SLOT))),
             'qrc_frozen_constants')
        nodes = []
        for name in wanted:
            hits = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
            need(len(hits) == 1 and not hits[0].decorator_list, 'qrc_definition')
            nodes.append(hits[0])
        subset = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
        exec(compile(subset, str(scoped(source_pin[0])), 'exec'), scope)
        scopes.extend(wanted)
    need(scopes == ['require', 'enumerate_qrc', 'patch_factory_ui'] and
         not any(name in scope for name in ('build', 'main', 'load_algorithms', 'write_new')),
         'old_builder_entry_forbidden')
    return scope['enumerate_qrc'], scope['patch_factory_ui']


def inventory(root, staged, pc_names):
    """Exact three-directory inventory; no arbitrary recursion or linked entries."""
    expected = set(staged) | set(pc_names)
    found = set()
    for name in STAGE_DIRECTORIES:
        folder = root if name == '' else root / name
        safe_directory(folder)
        with os.scandir(folder) as entries:
            for count, entry in enumerate(entries):
                need(count < 32, 'inventory_budget')
                value = entry.stat(follow_symlinks=False)
                need(not stat.S_ISLNK(value.st_mode) and
                     not getattr(value, 'st_file_attributes', 0) & 0x400, 'inventory_link')
                path = entry.name if name == '' else name + '/' + entry.name
                if path in ('mta', 'toolbox'):
                    need(name == '' and stat.S_ISDIR(value.st_mode), 'inventory_directory')
                else:
                    need(stat.S_ISREG(value.st_mode) and path in expected and path not in found,
                         'inventory_extra')
                    found.add(path)
    need(found == expected, 'inventory_incomplete')


def picker_delta(inputs, old_payload):
    spec = json.loads(inputs[PICKER_DELTA[0]])
    need(set(spec) == {'schema', 'evidence', 'source', 'candidate', 'bindings', 'replacements',
                       'runtime_source_only', 'deployed', 'actions_changed', 'native_changed'} and
         spec['schema'] == 'p011-formal-send-picker-generation-source-delta-v1' and
         spec['evidence'] == 'SOURCE_ONLY_NOT_EXECUTED' and spec['runtime_source_only'] is True and
         all(spec[name] is False for name in ('deployed', 'actions_changed', 'native_changed')) and
         spec['source'] == list(PICKER_MOTHER) and spec['candidate'] == list(PICKER) and
         spec['bindings'] == [[OLD_BUNDLE + '/mta/MtaHost.qml', PICKER_MOTHER[1], PICKER_MOTHER[2]]] and
         len(spec['replacements']) == 4, 'picker_delta_contract')
    before, after = inputs[PICKER_MOTHER[0]], inputs[PICKER[0]]
    need(before == old_payload['mta/MtaHost.qml'], 'actual_old_picker_binding')
    forward = before
    for row in spec['replacements']:
        need(set(row) == {'name', 'before', 'after', 'count'} and type(row['count']) is int and
             row['count'] == 1 and type(row['before']) is str and type(row['after']) is str, 'picker_delta_row')
        old, new = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        need(old != b'' and new != b'' and forward.count(old) == 1, 'picker_delta_unique')
        forward = forward.replace(old, new, 1)
    need(forward == after, 'picker_complete_forward')
    reverse = after
    for row in reversed(spec['replacements']):
        old, new = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        need(reverse.count(new) == 1, 'picker_inverse_unique')
        reverse = reverse.replace(new, old, 1)
    need(reverse == before, 'picker_complete_inverse')
    return spec


def cached_qt_evidence(inputs, payload_pins):
    value = json.loads(inputs[QT_RESULT[0]])
    need(value['schema'] == 'p011-receive-durable-affected-host-v1' and value['contract'] == 'picker' and
         value['passed'] is True and type(value['methods_run']) is int and value['methods_run'] == 1 and
         value['child_invocations'] == 1 and value['old_methods_requested'] == 0 and
         value['host_exit'] == value['child_exit'] == 0 and value['timeout'] is False and
         all(value[key] is False for key in ('deployed', 'device', 'rf', 'phone', 'full_graph',
                                           'real_mobile_transfer_verified', 'restoration_verified')) and
         value['remote_exit'] == 'NOT_RUN_HOST_ONLY' and value['source_preserved'] is True,
         'cached_qt_evidence')
    actual = {row['path']: (row['bytes'], row['sha256']) for row in value['inputs']}
    for fixed in (QT_TEST, QT_FIXTURE, PICKER, PICKER_DELTA, PICKER_MOTHER):
        need(actual.get(fixed[0]) == fixed[1:], 'cached_qt_input_binding')
    need(actual.get(OLD_BUNDLE + '/mta/MtaHost.qml') == PICKER_MOTHER[1:], 'cached_qt_out_binding')
    for name in ('MtaPage.qml', 'MtaKeyboard.qml', 'MtaButton.qml', 'MtaLabel.qml', 'MtaTheme.js'):
        need(actual.get('candidate/formal-send-filecenter-ui-v5/device/mta/' + name) ==
             payload_pins['mta/' + name], 'cached_qt_dependency_binding')
    need(b'self.host_only_case_count = 9' in inputs[QT_TEST[0]], 'cached_qt_nine_cases')
    return dict(result=list(QT_RESULT), existing_pass=True, methods=1, fixture_cases=9,
                reexecuted=False, boundary=value['boundary'], physical_rendering_verified=False,
                original_xhr_lifecycle_transport_executed=False)


def prepare():
    need(os.name == 'nt' and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1') and
         Path(__file__).resolve() == scoped(SELF), 'fixed_development_pc')
    safe_directory(scoped(ROOT))
    safe_directory(BASE / 'out')
    need(re.fullmatch(r'[0-9a-f]{24}', SESSION) is not None and SESSION != OLD_SESSION,
         'fresh_fixed_session')
    inputs = {path: read_pinned(scoped(path), (size, sha)) for path, size, sha in INPUT_PINS}
    original = read_pinned(PROJECT / ORIGINAL_PATH, ORIGINAL_PIN)
    original_key = 'PROJECT:' + ORIGINAL_PATH
    inputs[original_key] = original
    own = Path(__file__).read_bytes()
    need(0 < len(own) <= SOURCE_BUDGET, 'generator_source_budget')
    inputs[SELF] = own
    old_validator = inputs[OLD_VALIDATOR[0]]
    old_pins = literal(old_validator, 'PINS')
    old_manifest_pin = literal(old_validator, 'MANIFEST_PIN')
    need(literal(old_validator, 'SESSION') == OLD_SESSION and len(old_pins) == 18 and
         len({row[0] for row in old_pins}) == 18 and tuple(sorted(old_pins)) == old_pins and
         old_manifest_pin == (1603, '34cf33ad9ad501f49ac819856c4e0b3bb0e351d6eb0f82299402900962699df7') and
         all(relative(name) and type(size) is int and size > 0 and
             re.fullmatch(r'[0-9a-f]{64}', sha) is not None for name, size, sha in old_pins), 'old_validator_pins')
    old_stage_pins = tuple(sorted(old_pins + (('SOURCE.sha256',) + old_manifest_pin,)))
    stage = json.loads(inputs[OLD_STAGE[0]])
    need(stage['schema'] == 'p011-formal-send-filecenter-ui-v5-stage' and
         stage['session'] == OLD_SESSION and stage['remote'] == OLD_REMOTE and
         stage['payload_file_count'] == 18 and stage['staged_file_count'] == 19 and
         stage['directories'] == [dict(path=name, mode='0700') for name in STAGE_DIRECTORIES] and
         tuple((row['path'], row['bytes'], row['sha256']) for row in stage['files']) == old_stage_pins and
         all(row['mode'] == ('0500' if row['path'] == 'Z03.mta-ui-candidate' else '0400') for row in stage['files']) and
         stage['excluded_pc_files'] == list(PC_NAMES) and stage['credentials_in_stage'] is False and
         stage['font_files_bundled'] is False, 'old_stage_contract')
    old_root = scoped(OLD_BUNDLE)
    inventory(old_root, [row[0] for row in old_stage_pins], PC_NAMES)
    old_files = {}
    for name, size, sha in old_stage_pins:
        raw = read_pinned(old_root / name, (size, sha))
        inputs[OLD_BUNDLE + '/' + name] = raw
        old_files[name] = raw
    need(old_files['SOURCE.sha256'] == ''.join(sha + ' ' + str(size) + ' ' + name + '\n'
         for name, size, sha in old_pins).encode('ascii') and
         sum(map(len, old_files.values())) == 4184498, 'old_actual_bundle_manifest')
    old_payload = {name: raw for name, raw in old_files.items() if name != 'SOURCE.sha256'}
    spec = picker_delta(inputs, old_payload)
    cached = cached_qt_evidence(inputs, {name: (size, sha) for name, size, sha in old_pins})
    enumerate_resources, patch_factory = pure_qrc(inputs)
    old_elf, old_nav, old_used = patch_factory(original, OLD_REMOTE, enumerate_resources)
    need(old_elf == old_payload['Z03.mta-ui-candidate'] and old_nav == inputs[OLD_NAV[0]] and
         old_used == 1567, 'old_elf_actual_source_binding')
    old_build = json.loads(inputs[OLD_BUILD[0]])
    need(old_build['candidate_bytes'] == len(old_elf) and old_build['candidate_sha256'] == digest(old_elf) and
         old_build['builder_sha256'] == BUILDER[2] and old_build['session'] == OLD_SESSION and
         old_build['remote'] == OLD_REMOTE and old_build['original_sha256'] == ORIGINAL_PIN[1] and
         old_build['used_bytes'] == old_used and old_build['resources_verified'] == 400 and
         old_build['other_resources_original_bytes'] == 399 and old_build['device_tested'] is False,
         'old_build_evidence')
    new_elf, new_nav, used = patch_factory(original, REMOTE, enumerate_resources)
    end = NAV_OFFSET + 4 + NAV_SLOT
    original_resources = enumerate_resources(original)
    new_resources = enumerate_resources(new_elf)
    need(len(new_elf) == ORIGINAL_PIN[0] and new_elf[:NAV_OFFSET] == original[:NAV_OFFSET] and
         new_elf[end:] == original[end:] and new_elf[:NAV_OFFSET] == old_elf[:NAV_OFFSET] and
         new_elf[end:] == old_elf[end:] and len(original_resources) == len(new_resources) == 400 and
         set(original_resources) == set(new_resources) and
         sum(new_resources[name] == body for name, body in original_resources.items()
             if name != '/NaviPanel.qml') == 399 and 0 < used <= NAV_SLOT,
         'new_elf_400_399_same_slot')
    need(old_nav.count(OLD_REMOTE.encode('ascii')) == 1 and
         new_nav == old_nav.replace(OLD_REMOTE.encode('ascii'), REMOTE.encode('ascii'), 1) and
         new_nav.replace(REMOTE.encode('ascii'), OLD_REMOTE.encode('ascii'), 1) == old_nav,
         'nav_root_only_forward_inverse')
    files = dict(old_payload)
    files['mta/MtaHost.qml'] = inputs[PICKER[0]]
    files['Z03.mta-ui-candidate'] = new_elf
    text_proofs = []
    for name, count in (('Bridge.qml', 1), ('FormalEntry.qml', 2)):
        old = old_payload[name]
        need(old.count(OLD_SESSION.encode('ascii')) == count, 'entry_session_count')
        new = old.replace(OLD_SESSION.encode('ascii'), SESSION.encode('ascii'))
        need(new.count(SESSION.encode('ascii')) == count and
             new.replace(SESSION.encode('ascii'), OLD_SESSION.encode('ascii')) == old and
             len(new) == len(old), 'entry_complete_inverse')
        files[name] = new
        text_proofs.append(dict(path=name, changed_literal='SESSION', occurrences=count,
                                complete_forward_inverse=True))
    need(set(files) == set(old_payload) and tuple(sorted(name for name in files
         if files[name] != old_payload[name])) == PAYLOAD_CHANGED and
         sum(files[name] == old_payload[name] for name in files) == 14 and
         files['mta/MtaHost.qml'] == inputs[PICKER[0]], 'exact_payload_delta')
    for name, raw in files.items():
        if name != 'Z03.mta-ui-candidate':
            need(name.endswith(('.qml', '.js')) and b'\0' not in raw and
                 re.search(rb'@[A-Z_]+@', raw) is None and OLD_SESSION.encode('ascii') not in raw,
                 'qml_text_no_old_identity')
            raw.decode('utf-8')
    need(sum(len(raw) for path, raw in inputs.items() if not path.startswith('PROJECT:') and
             not path.endswith('Z03.mta-ui-candidate')) <= SOURCE_BUDGET, 'all_text_input_budget')
    pins = tuple((name, len(raw), digest(raw)) for name, raw in sorted(files.items()))
    source = ''.join(sha + ' ' + str(size) + ' ' + name + '\n' for name, size, sha in pins).encode('ascii')
    need(len(source) <= 4096 and len(source.splitlines()) == 18, 'source_manifest_budget')
    staged = dict(files, **{'SOURCE.sha256': source})
    stage_pins = tuple((name, len(raw), digest(raw)) for name, raw in sorted(staged.items()))
    asset_bytes = sum(len(raw) for raw in staged.values())
    need(len(staged) == 19 and asset_bytes <= STAGE_BUDGET, 'stage_19file_4mib_cap')
    pins_expression = '(\n' + ''.join('    ' + repr(row) + ',\n' for row in pins) + ')'
    validator, validator_proof = constant_overlay(old_validator,
        {'SESSION': repr(SESSION), 'MANIFEST_PIN': repr((len(source), digest(source))),
         'PINS': pins_expression}, 'validator')
    guardian, guardian_proof = constant_overlay(inputs[OLD_GUARDIAN[0]],
        {'SESSION': repr(SESSION), 'CONTROL_NAME': "'p011-mta-ui-session-' + SESSION + " + repr(CONTROL_SUFFIX)},
        'guardian')
    need(literal(validator, 'SESSION') == literal(guardian, 'SESSION') == SESSION and
         literal(validator, 'PINS') == pins and literal(validator, 'MANIFEST_PIN') == (len(source), digest(source)) and
         b'CONTROL = \'/var/volatile/tmp/\' + CONTROL_NAME' in guardian and
         b'CANDIDATE = ASSETS + \'/Z03.mta-ui-candidate\'' in guardian,
         'runtime_identity_closure')
    for raw in (validator, guardian):
        ast.parse(raw, feature_version=(3, 5))
        need(max(map(len, raw.splitlines())) <= 2048, 'target_source_line_cap')
    next_stage = dict(stage)
    next_stage.update(schema='p011-formal-send-picker-package-v1-stage', session=SESSION, remote=REMOTE,
        source_manifest=dict(path='SOURCE.sha256', bytes=len(source), sha256=digest(source),
                             format='sha256 space decimal-bytes space relative-path LF'),
        files=[dict(path=name, bytes=size, sha256=sha, mode='0500' if name == 'Z03.mta-ui-candidate' else '0400')
               for name, size, sha in stage_pins])
    outputs = {BUNDLE + '/' + name: raw for name, raw in staged.items()}
    outputs[BUNDLE + '/NaviPanel.embedded.qml'] = new_nav
    outputs[BUNDLE + '/stage-manifest.json'] = json_raw(next_stage)
    outputs[VALIDATOR], outputs[GUARDIAN] = validator, guardian
    build_result = dict(schema='p011-formal-send-picker-package-v1-pc-build',
        evidence_level='PC_SOURCE_COMPUTED_NOT_DEVICE', session=SESSION, remote=REMOTE,
        original_path=ORIGINAL_PATH, original_bytes=ORIGINAL_PIN[0], original_sha256=ORIGINAL_PIN[1],
        candidate_bytes=len(new_elf), candidate_sha256=digest(new_elf),
        source_manifest_files=18, source_manifest_bytes=len(source), source_manifest_sha256=digest(source),
        staged_file_count=19, staged_directory_count=3, asset_bytes=asset_bytes, stage_spare=STAGE_BUDGET - asset_bytes,
        source_ui_files=16, source_qml_files=14, source_js_files=2,
        changed_resource='/NaviPanel.qml', resources_verified=400, other_resources_original_bytes=399,
        record_offset=NAV_OFFSET, slot_bytes=NAV_SLOT, used_bytes=used, slot_spare=NAV_SLOT - used,
        elf_total_length_unchanged=True, elf_outside_slot_unchanged=True, compressed_qml_readback=True,
        old_bundle=list(OLD_BUILD), old_bundle_bytes_verified=True, payload_changed=list(PAYLOAD_CHANGED),
        unchanged_payload_files=14, tested_picker_exact_copy=list(PICKER), picker_delta=list(PICKER_DELTA),
        reused_pure_definitions=['require', 'enumerate_qrc', 'patch_factory_ui'],
        old_builder_invoked=False, old_main_invoked=False, old_tests_reexecuted=False,
        cached_picker_qt_evidence=cached, factory_keyboard_reference='original vk supplied explicitly by fixed NaviPanel Loader',
        factory_keyboard_runtime_verified=False, geometry='parent-owned 800x268; no additional offset or rotation',
        builder_sha256=digest(own), validator=list(pin(VALIDATOR, validator)), guardian=list(pin(GUARDIAN, guardian)),
        credentials_in_stage=False, font_files_bundled=False, original_files_changed=False, startup_changed=False,
        device_tested=False, qml_runtime_verified=False, native_component_verified=False,
        companion_connected=False, receive_tested=False, send_tested=False, radio_admission_issued=False,
        phone_interop_verified=False, stock_restoration_verified=False, sender_default_tab=True,
        independent_receiver_entry_required=True, docker_invoked=False, sdk_invoked=False,
        worker_generated=False, ordinary_sender_generated=False, deployed=False)
    outputs[BUNDLE + '/build-result.json'] = json_raw(build_result)
    input_rows = [list(pin(path, raw)) for path, raw in sorted(inputs.items())]
    generation = dict(schema='p011-formal-send-picker-package-generation-v1',
        status='PC_SOURCE_COMPUTED_NOT_DEVICE', session=SESSION, remote=REMOTE,
        bundle=BUNDLE, control_name=CONTROL_NAME, control=CONTROL, control_suffix=CONTROL_SUFFIX,
        source_manifest=list(pin(BUNDLE + '/SOURCE.sha256', source)),
        stage_manifest=list(pin(BUNDLE + '/stage-manifest.json', outputs[BUNDLE + '/stage-manifest.json'])),
        asset_bytes=asset_bytes, stage_file_count=19, payload_file_count=18, unchanged_payload_files=14,
        changed_payload=list(PAYLOAD_CHANGED), picker_replacements=spec['replacements'],
        picker_complete_forward_inverse=True, entry_complete_forward_inverse=text_proofs,
        validator_constant_replacements=validator_proof, guardian_constant_replacements=guardian_proof,
        runtime_complete_byte_ast_inverse=True, runtime_all_definitions_bytes_and_line_numbers_unchanged=True,
        qrc_400_verified=True, other_399_original_records_unchanged=True,
        original_elf_same_slot=True, old_bundle_same_slot=True, nav_root_only_complete_inverse=True,
        output_pins=[list(pin(path, raw)) for path, raw in sorted(outputs.items())], inputs=input_rows,
        cached_picker_qt_evidence=cached, caps=dict(input_text_bytes=SOURCE_BUDGET, stage_bytes=STAGE_BUDGET,
              source_manifest_bytes=4096, target_max_line=2048, file_bytes=FILE_BUDGET,
              qrc_slot_bytes=NAV_SLOT, geometry='800x268'),
        old_builders=0, old_mains=0, old_tests=0, worker_generated=False, ordinary_sender_generated=False,
        device=False, rf=False, stage_device=False, ui_runtime=False, deployed=False,
        failed_partial_outputs_preserved=True, new_outputs_exclusive=True,
        needs_root_worker_outer_pin_integration=True, needs_new_host_stage_capture_binding=True)
    outputs[GENERATION] = json_raw(generation)
    need(len(outputs) == 25 and all(path.startswith(BUNDLE + '/') or path in (VALIDATOR, GUARDIAN, GENERATION)
         for path in outputs) and all(type(raw) is bytes and 0 < len(raw) <= FILE_BUDGET for raw in outputs.values()),
         'new_output_partition')
    inventory(old_root, [row[0] for row in old_stage_pins], PC_NAMES)
    verify_inputs(inputs)
    return outputs, generation, inputs


def verify_inputs(inputs):
    for path, raw in inputs.items():
        target = PROJECT / path[len('PROJECT:'):] if path.startswith('PROJECT:') else scoped(path)
        need(read_pinned(target, (len(raw), digest(raw))) == raw, 'input_preserved:' + path)


def write_new(path, raw):
    safe_directory(path.parent)
    with path.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'output_short_write')
    need(read_pinned(path, (len(raw), digest(raw))) == raw, 'output_readback')


def main():
    need(sys.argv[1:] in ([], ['--write']), 'only_explicit_write_option')
    writing = sys.argv[1:] == ['--write']
    outputs, report, inputs = prepare()
    if writing:
        # Check every fixed destination before creating either new subtree.
        for folder in (scoped(BUNDLE), scoped(ROOT + '/runtime')):
            safe_directory(folder.parent)
            need(not folder.exists() and not folder.is_symlink(), 'exclusive_output_directory')
        need(not scoped(GENERATION).exists() and not scoped(GENERATION).is_symlink(), 'exclusive_generation')
        for path in outputs:
            need(not scoped(path).exists() and not scoped(path).is_symlink(), 'exclusive_output_file')
        verify_inputs(inputs)
        scoped(BUNDLE).mkdir(exist_ok=False)
        for name in ('mta', 'toolbox'):
            (scoped(BUNDLE) / name).mkdir(exist_ok=False)
        scoped(ROOT + '/runtime').mkdir(exist_ok=False)
        for path, raw in outputs.items():
            write_new(scoped(path), raw)
        inventory(scoped(BUNDLE), [row[0].split(BUNDLE + '/', 1)[1] for row in report['output_pins']
                  if row[0].startswith(BUNDLE + '/') and row[0].split(BUNDLE + '/', 1)[1] not in PC_NAMES], PC_NAMES)
        # The bundle contains its three PC diagnostics, never staged remotely.
        verify_inputs(inputs)
    print(json.dumps(dict(mode='WRITE_EXCLUSIVE_PC_ONLY' if writing else 'SOURCE_ONLY_NO_WRITES',
        session=SESSION, remote=REMOTE, control=CONTROL, bundle=BUNDLE,
        output_count=len(outputs), outputs=[list(pin(path, raw)) for path, raw in sorted(outputs.items())],
        asset_bytes=report['asset_bytes'], stage_spare=STAGE_BUDGET - report['asset_bytes'],
        worker_generated=False, device=False, rf=False, old_builders=0, old_mains=0, old_tests=0),
        sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
