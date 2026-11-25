"""PC-only mechanical sender package for the FileCenter HTTP parent cap.

prepare() only reads fixed sources and assembles bytes. It never imports or
executes a runtime, old generator, test, builder, Stage, HOST or device entry.
--write is a separate explicit PC publication: missing files use EXCL; any
existing target must already be identical. Conflicts/partial data are retained.
This is source linkage, not Stage, runtime, restoration, RF or phone evidence.
The receive family and the existing 19-file GUI bundle are never modified.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

BASE = Path(__file__).resolve().parents[2]
ROOT = 'candidate/formal-send-fc-http-cap-v1'
SELF = ROOT + '/generate_package.py'
OLD = 'candidate/formal-send-filecenter-deploy-v7'
UI_OLD = 'candidate/formal-send-status-package-v3'
OLD_NAME = 'p011-mta-formal-send-filecenter-deploy-v7'
NEW_NAME = 'p011-mta-formal-send-filecenter-httpcp-v1'
OLD_REMOTE = '/tmp/' + OLD_NAME
NEW_REMOTE = '/tmp/' + NEW_NAME
OLD_PHYSICAL = '/var/volatile/tmp/' + OLD_NAME
NEW_PHYSICAL = '/var/volatile/tmp/' + NEW_NAME
OLD_CONTROL_SUFFIX = '-formal-send-status-package-v3'
NEW_CONTROL_SUFFIX = '-formal-send-fc-http-cap-v1'
SESSION = '6d4fb1fd4af949cbb3515870'
BUNDLE = 'out/mta-ui-send-status-v1-' + SESSION
FC_MANIFEST = ROOT + '/assets/filecenter-source-manifest.json'
ORDINARY_MANIFEST = ROOT + '/assets/ordinary-source-manifest.json'
DELTA = ROOT + '/exactsource-delta.json'
GENERATION = ROOT + '/generation.json'
FILE_CAP = 2 * 1024 * 1024
SOURCE_PINS = (
    ('candidate/formal-send-preflight-native-graph-v1/generate_graph.py', 35171,
     '6379b0ca7543fd4c23c691848acb65e4ebae0d538bb6070f46471b8127814a87'),
    (UI_OLD + '/generate_ui.py', 12871,
     '07788d35b2eccd7cdd68877b6b854efbb9a02ddf08f282c0295e71939e4888a7'),
    ('candidate/formal-send-status-package-v1/generate_ui.py', 24159,
     'a424b9b28583797ea669beb983437a9ad6a277d527cc808f6160775a6810980c'),
    (OLD + '/assets/ordinary-source-manifest.json', 20810,
     '9be61347f4a44d031cf7c07095692b4cd0de21f79410a9f45c5ad6b2073f9d52'),
    (OLD + '/assets/asset-sources.json', 24365,
     '76368b95981aa206eeb2a7eaa929fb1263a3ffd94d78b8757422626baab3db73'),
    ('candidate/formal-send-filecenter-deploy-v3/assets/filecenter-source-manifest.json', 2466,
     '14d57b5aea7c49df0f87b6338044c86ccd155583994e83c8158c5217d7f48e1d'),
    (OLD + '/runtime/mta_client_receive_boot.py', 19583,
     '6b551fe2b8a90fe1bbaf3cfec2a85b3a9bdb8315d38191e71c1f7f31c20065a6'),
    (OLD + '/runtime/mta_client_service_owner.py', 103959,
     'b73f30f0899efc96f363b7889ff79a5c92d48fd28c73796423bdcb40230e7761'),
    (OLD + '/runtime/formal_send_session.py', 24060,
     '6cbd71d7ce054df6de4c419cd93c0ac8ba2049b2f7f9b692bd10bfb2af3b148f'),
    (OLD + '/runtime/formal_send_stage.py', 37421,
     'eafc45ced6c0b4b0598b9bfb6fc86adefed68a5b94137303ca91d2256e7adc14'),
    (UI_OLD + '/runtime/ui_assets.py', 12526,
     '430308223593d5d783c1ec1d29a90dcbe82606b33690fc263572b8353d9fd4e8'),
    (UI_OLD + '/runtime/ui_guardian.py', 43994,
     'c36560f4d481677ce61ec9cbed5910f4f202e381215a4cd5f2eb564965712998'),
    (UI_OLD + '/runtime/ui_session.py', 46416,
     'adc1561cd32d53257c5df123c4516c63e38198a7c08a04be0fc51249d2893c25'),
    ('candidate/filecenter-http-parent-cap-v1/send/mta_filecenter_companion.py', 26088,
     '5daa53f647db195f02a5588f0fb45d009b490eaa51d0af98de76205b00fdee0f'),
    ('candidate/filecenter-http-parent-cap-v1/shared/mta_toolbox_minhttp.py', 9323,
     '8ea06020e4b133665ab881e5901af9094ebc2c9d5add9d4eb37ca5b2e55a8c55'),
)
ROOT_ROLES = ('mta_send_trial', 'mta_send_terminal_consumer', 'mta_service')
STARTUP_ROLES = ('mta_client_receive_boot', 'mta_client_service_owner', 'formal_send_session')
FC_NEW = {
    'mta_toolbox_minhttp': SOURCE_PINS[-1],
    'mta_filecenter_companion': SOURCE_PINS[-2],
}


def need(condition, code):
    if condition is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, raw):
    return (path, len(raw), digest(raw))


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def metadata(value):
    return tuple(getattr(value, key) for key in
        ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def relative(value):
    need(type(value) is str and value and '\\' not in value and ':' not in value and
         not value.startswith('/') and all(row not in ('', '.', '..') for row in value.split('/')),
         'relative_path')
    return BASE / value


def directories(path):
    for node in reversed((path,) + tuple(path.parents)):
        value = node.lstat()
        need(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
             not getattr(value, 'st_file_attributes', 0) & 0x400, 'directory_identity')


def read(path, expected):
    """Single-link held-source read; no mode repair or broad path allowance."""
    location = relative(path)
    directories(location.parent)
    before = location.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         not stat.S_ISLNK(before.st_mode) and not getattr(before, 'st_file_attributes', 0) & 0x400 and
         0 < before.st_size <= 5 * 1024 * 1024 and before.st_size == expected[0], 'file_identity')
    with location.open('rb') as stream:
        opened = metadata(os.fstat(stream.fileno()))
        # Windows path/handle creation-time presentation is interface-local;
        # identity/mode/length/mtime are exact, and each full interface stays stable.
        need(opened[:6] == metadata(before)[:6] if os.name == 'nt' else opened == metadata(before),
             'opened_identity')
        raw = stream.read(expected[0] + 1)
        need(metadata(os.fstat(stream.fileno())) == opened and metadata(location.lstat()) == metadata(before),
             'held_source_changed')
    need(metadata(location.lstat()) == metadata(before) and (len(raw), digest(raw)) == tuple(expected),
         'source_pin')
    return raw


def take(inputs, row):
    path, size, sha = row
    need(type(size) is int and 0 < size <= 5 * 1024 * 1024 and
         type(sha) is str and re.fullmatch('[0-9a-f]{64}', sha) is not None, 'pin_shape')
    raw = read(path, (size, sha))
    need(path not in inputs or inputs[path] == raw, 'source_consistency')
    inputs[path] = raw
    return raw


def preserve(inputs):
    for path, raw in inputs.items():
        need(read(path, (len(raw), digest(raw))) == raw, 'input_preserved')


def parse(raw):
    return ast.parse(raw.decode('utf-8'), feature_version=(3, 5))


def literal(raw, name):
    rows = [node for node in parse(raw).body if isinstance(node, ast.Assign) and
            len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(rows) == 1, 'unique_literal')
    return ast.literal_eval(rows[0].value)


def expression(raw, name):
    rows = [node for node in parse(raw).body if isinstance(node, ast.Assign) and
            len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(rows) == 1, 'unique_expression')
    return ast.dump(rows[0].value, include_attributes=False)


def functions(raw):
    rows, positions = {}, []
    lines = raw.splitlines(keepends=True)
    def visit(nodes, parent):
        for node in nodes:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                name = parent + node.name
                positions.append((name, type(node).__name__, node.lineno, node.end_lineno))
                if isinstance(node, ast.FunctionDef):
                    start = sum(map(len, lines[:node.lineno - 1])) + node.col_offset
                    end = sum(map(len, lines[:node.end_lineno - 1])) + node.end_col_offset
                    rows[name] = raw[start:end]
                visit(node.body, name + '.')
    visit(parse(raw).body, '')
    return rows, positions


class Edit(object):
    """Every substitution has a finite count and a full inverse byte receipt."""
    def __init__(self, source, raw):
        self.source, self.original, self.raw, self.steps = source, raw, raw, []

    def change(self, before, after, count=1, label='constant'):
        before = before.encode('utf-8') if type(before) is str else before
        after = after.encode('utf-8') if type(after) is str else after
        need(type(before) is bytes and type(after) is bytes and before and after and before != after and
             type(count) is int and 0 < count <= 100 and self.raw.count(before) == count and
             self.raw.count(after) == 0, 'substitution_anchor')
        need(before.count(b'\n') == after.count(b'\n'), 'line_count_preserved')
        self.raw = self.raw.replace(before, after, count)
        self.steps.append(dict(label=label, before=before.decode('utf-8'), after=after.decode('utf-8'), count=count))

    def pin_constant(self, name, old, new):
        need(literal(self.raw, name) == old, 'old_pin_constant')
        self.change(name + ' = ' + repr(old), name + ' = ' + repr(new), label=name)
        need(literal(self.raw, name) == new, 'new_pin_constant')

    def hash_constant(self, old, new, label):
        need(type(old) is str and type(new) is str and len(old) == len(new) == 64, 'hash_shape')
        self.change(old, new, label=label)

    def finish(self, target, allowed_functions=()):
        inverse = self.raw
        for step in reversed(self.steps):
            before, after = step['before'].encode('utf-8'), step['after'].encode('utf-8')
            need(inverse.count(after) == step['count'], 'inverse_anchor')
            inverse = inverse.replace(after, before, step['count'])
        need(inverse == self.original and ast.dump(parse(inverse), include_attributes=True) ==
             ast.dump(parse(self.original), include_attributes=True), 'whole_byte_ast_inverse')
        old_functions, old_positions = functions(self.original)
        new_functions, new_positions = functions(self.raw)
        changed = tuple(name for name in old_functions if old_functions[name] != new_functions[name])
        need(old_positions == new_positions and set(old_functions) == set(new_functions) and
             changed == tuple(allowed_functions) and max(map(len, self.raw.splitlines())) <= 2048 and
             0 < len(self.raw) <= FILE_CAP, 'method_scope')
        return self.raw, dict(source=list(pin(self.source, self.original)), candidate=list(pin(target, self.raw)),
            substitutions=self.steps, complete_byte_ast_inverse=True, definition_lines_unchanged=True,
            changed_definition_constants=list(changed), other_definition_bytes_unchanged=True)


def record(row):
    return (row['source'], row['bytes'], row['sha256'])


def fc_pins(rows):
    return tuple((row['module'], row['bytes'], row['sha256']) for row in rows)


def replace_fc(edit, old_rows, new_rows):
    need(literal(edit.raw, 'FILECENTER_PINS') == fc_pins(old_rows), 'old_filecenter_closure')
    for old, new in zip(fc_pins(old_rows), fc_pins(new_rows)):
        if old != new:
            edit.change(repr(old), repr(new), label='FILECENTER_PINS.' + old[0])
    need(literal(edit.raw, 'FILECENTER_PINS') == fc_pins(new_rows), 'new_filecenter_closure')


def ordinary_rows(catalog):
    rows = []
    for group in ('sources', 'startup_sources', 'helper_sources'):
        for row in catalog[group]:
            if row.get('reused_sender_asset') is True:
                continue
            need(row['physical_target'].startswith(catalog['physical_ordinary_root'][:-8] + '/'),
                 'ordinary_target_scope')
            rows.append((row['physical_target'][len(catalog['physical_ordinary_root'][:-8]) + 1:],
                         row['bytes'], row['sha256'], row['mode']))
    return tuple(rows)


def json_change(raw, changes, expected, target, source):
    current, steps = raw, []
    for before, after, count, label in changes:
        before, after = before.encode('utf-8'), after.encode('utf-8')
        need(before and before != after and current.count(before) == count and current.count(after) == 0,
             'json_substitution')
        current = current.replace(before, after, count)
        steps.append(dict(label=label, before=before.decode('utf-8'), after=after.decode('utf-8'), count=count))
    inverse = current
    for step in reversed(steps):
        old, new = step['before'].encode('utf-8'), step['after'].encode('utf-8')
        need(inverse.count(new) == step['count'], 'json_inverse_anchor')
        inverse = inverse.replace(new, old, step['count'])
    need(inverse == raw and json.loads(current) == expected, 'json_full_inverse_expected')
    return current, dict(source=list(pin(source, raw)), candidate=list(pin(target, current)),
                         substitutions=steps, complete_byte_inverse=True, parsed_expected=True)


def json_record_text(row, indent):
    return ('"source": ' + json.dumps(row['source']) + ',\n' + indent + '"bytes": ' + str(row['bytes']) +
            ',\n' + indent + '"sha256": ' + json.dumps(row['sha256']))


def prepare():
    """Pure read/assembly entry used by the independent Root SOURCE checker."""
    need(Path(__file__).resolve() == BASE / SELF and len(OLD_NAME) == len(NEW_NAME) and
         OLD_NAME != NEW_NAME and ROOT != OLD and ROOT != UI_OLD, 'independent_package')
    inputs = {}
    for row in SOURCE_PINS:
        take(inputs, row)
    own = relative(SELF)
    own_size = own.lstat().st_size
    need(0 < own_size <= 262144, 'generator_cap')
    own_raw = own.read_bytes()
    need(len(own_raw) == own_size, 'generator_length_stable')
    take(inputs, pin(SELF, own_raw))
    old_catalog = json.loads(inputs[SOURCE_PINS[3][0]])
    assets = json.loads(inputs[SOURCE_PINS[4][0]])
    old_fc = json.loads(inputs[SOURCE_PINS[5][0]])
    need(old_catalog['schema'] == 'p011-formal-send-filecenter-deploy-v7-ordinary-source-catalog' and
         old_catalog['ordinary_root'] == OLD_REMOTE + '/runtime' and
         old_catalog['physical_ordinary_root'] == OLD_PHYSICAL + '/runtime' and
         old_catalog['source_count'] == len(old_catalog['sources']) == 32 and
         len(old_catalog['startup_sources']) == len(old_catalog['helper_sources']) == 3 and
         old_catalog['ordinary_source_bytes'] == sum(row['bytes'] for row in old_catalog['sources']) == 1078691 and
         old_catalog['ordinary_batch_files'] == 37 and old_catalog['ordinary_batch_bytes'] == 1368142 and
         old_catalog['original_boot_load_seconds'] == 10 and
         old_catalog['original_per_source_cap_bytes'] == old_catalog['program_cap_bytes'] == FILE_CAP and
         old_catalog['wire_cap_bytes'] == 4 * 1024 * 1024 and
         all(old_catalog[key] is False for key in ('runtime', 'host_graph_tested', 'native', 'rf', 'phone', 'production')),
         'actual_v7_catalog')
    need(record(old_catalog['filecenter_source_manifest']) == SOURCE_PINS[5] and
         record(old_catalog['separate_asset_catalog']) == SOURCE_PINS[4] and
         old_catalog['filecenter_source_delivery'] == old_fc['delivery'] == 'separate-fixed-memory-nine-source-caller' and
         old_fc['source_count'] == len(old_fc['sources']) == 9 and old_fc['source_bytes'] == 99972 and
         old_fc['source_cap'] == 131072 and old_fc['in_protocol_stage_payload'] is False,
         'separate_filecenter_sources')
    need(assets['sender_source_count'] == len(assets['sender_sources']) == 25 and
         assets['observer_source_count'] == len(assets['observer_sources']) == 41 and
         assets['observer_load_count'] == 38 and assets['sender_root'] != OLD_PHYSICAL and
         assets['observer_root'] != OLD_PHYSICAL, 'independent_assets')
    for row in (old_catalog['sources'] + old_catalog['startup_sources'] + old_catalog['helper_sources'] +
                old_fc['sources'] + assets['sender_sources'] + assets['observer_sources'] +
                [assets['wpa'], assets['sender_manifest']]):
        take(inputs, record(row))
    # Metadata-table provenance is authenticated too, without selecting an older Owner.
    for key in ('sender_source_table', 'observer_source_table', 'original_observer_source_table'):
        take(inputs, tuple(assets[key]))
    startup = {row['module']: row for row in old_catalog['startup_sources']}
    sources = {row['module']: row for row in old_catalog['sources']}
    need(tuple(startup) == STARTUP_ROLES and len(sources) == 32 and
         tuple(record(startup[name]) for name in STARTUP_ROLES) == SOURCE_PINS[6:9], 'actual_startup_source')
    boot, owner, outer = (inputs[startup[name]['source']] for name in STARTUP_ROLES)
    stage, validator, guardian, worker = (inputs[SOURCE_PINS[index][0]] for index in (9, 10, 11, 12))
    need(literal(boot, 'SOURCE_PINS') == fc_pins(old_catalog['sources']) and
         literal(owner, 'BOOT_PIN') == literal(outer, 'BOOT_PIN') == SOURCE_PINS[6][1:] and
         literal(outer, 'OWNER_PIN') == SOURCE_PINS[7][1:] and
         literal(worker, 'SENDER_PIN') == SOURCE_PINS[8][1:] and
         literal(worker, 'GUARDIAN_PIN') == SOURCE_PINS[11][1:] and
         literal(worker, 'ASSETS_PIN') == SOURCE_PINS[10][1:] and
         literal(owner, 'FILECENTER_PINS') == literal(worker, 'FILECENTER_PINS') == fc_pins(old_fc['sources']),
         'actual_owner_worker_pin_chain')
    need(literal(boot, 'LOAD_SECONDS') == 10.0 and literal(owner, 'CLEANUP_SECONDS') == 60.0 and
         literal(owner, 'FILECENTER_MAX_SOURCE') == 131072 and literal(stage, 'MAX_SECONDS') == 120.0 and
         expression(stage, 'RAW_LIMIT') == ast.dump(ast.parse('4 * 1024 * 1024', mode='eval').body,
                                                   include_attributes=False) and
         literal(outer, 'PROFILES') == (('diagnostic', 60.0, False), ('send-interactive-v1', 600.0, True)) and
         literal(worker, 'SENDER_ROOT') == OLD_REMOTE and literal(worker, 'SENDER_PHYSICAL_ROOT') == OLD_PHYSICAL,
         'constant_caps')
    old_profiles, old_totals = literal(stage, 'PROFILE_FILES'), literal(stage, 'PROFILE_TOTALS')
    need(tuple(row[0] for row in old_profiles) == ('sender', 'observer', 'ordinary') and
         old_profiles[2] == ('ordinary', OLD_PHYSICAL, ordinary_rows(old_catalog)) and
         old_totals == (('sender', 27, 2402458), ('observer', 41, 1548495), ('ordinary', 37, 1368142)),
         'actual_stage_inventory')
    # The GUI is a readonly reused prerequisite; no QRC/rebuild/restage path here.
    ui_pins = literal(validator, 'PINS')
    manifest_pin = literal(validator, 'MANIFEST_PIN')
    need(literal(validator, 'SESSION') == literal(guardian, 'SESSION') == literal(worker, 'SESSION') == SESSION and
         len(ui_pins) == 18 and tuple(sorted(ui_pins)) == ui_pins, 'same_gui_identity')
    for name, size, sha in ui_pins + (('SOURCE.sha256',) + manifest_pin,):
        take(inputs, (BUNDLE + '/' + name, size, sha))
    need(inputs[BUNDLE + '/SOURCE.sha256'] == ''.join(sha + ' ' + str(size) + ' ' + name + '\n'
         for name, size, sha in ui_pins).encode('ascii') and
         sum(len(inputs[BUNDLE + '/' + name]) for name, size, sha in
             ui_pins + (('SOURCE.sha256',) + manifest_pin,)) == 4185296, 'same_gui_readback')
    new_fc = json.loads(inputs[SOURCE_PINS[5][0]])
    for row in new_fc['sources']:
        if row['module'] in FC_NEW:
            row.update(source=FC_NEW[row['module']][0], bytes=FC_NEW[row['module']][1], sha256=FC_NEW[row['module']][2])
    new_fc['schema'] = 'p011-formal-send-fc-http-cap-v1-filecenter-source'
    new_fc['source_bytes'] = sum(len(inputs[row['source']]) for row in new_fc['sources'])
    need(new_fc['source_bytes'] == 100114 and new_fc['source_bytes'] <= new_fc['source_cap'] and
         sum(old != new for old, new in zip(old_fc['sources'], new_fc['sources'])) == 2, 'two_source_fc_delta')
    outputs, deltas, new_roles = {}, [], {}
    def finish(edit, module, allowed=()):
        target = ROOT + '/runtime/' + module + '.py'
        raw, proof = edit.finish(target, allowed)
        outputs[target], new_roles[module] = raw, pin(target, raw)
        deltas.append(proof)
        return raw
    for name in ROOT_ROLES:
        edit = Edit(sources[name]['source'], inputs[sources[name]['source']])
        edit.change(OLD_NAME, NEW_NAME, label='independent_ordinary_root')
        raw = finish(edit, name)
        need(len(raw) == sources[name]['bytes'], 'equal_length_role')
    edit = Edit(SOURCE_PINS[6][0], boot)
    edit.change(OLD_NAME, NEW_NAME, 2, 'independent_ordinary_root')
    for name in ROOT_ROLES:
        edit.hash_constant(sources[name]['sha256'], new_roles[name][2], 'SOURCE_PINS.' + name)
    new_boot = finish(edit, STARTUP_ROLES[0])
    edit = Edit(SOURCE_PINS[7][0], owner)
    edit.change(OLD_NAME, NEW_NAME, 2, 'independent_ordinary_root_and_anchor')
    edit.pin_constant('BOOT_PIN', SOURCE_PINS[6][1:], new_roles[STARTUP_ROLES[0]][1:])
    replace_fc(edit, old_fc['sources'], new_fc['sources'])
    new_owner = finish(edit, STARTUP_ROLES[1], ('_LinuxIo._anchors',))
    edit = Edit(SOURCE_PINS[8][0], outer)
    edit.change(OLD_NAME, NEW_NAME, 2, 'independent_ordinary_root')
    edit.pin_constant('BOOT_PIN', SOURCE_PINS[6][1:], new_roles[STARTUP_ROLES[0]][1:])
    edit.pin_constant('OWNER_PIN', SOURCE_PINS[7][1:], new_roles[STARTUP_ROLES[1]][1:])
    new_outer = finish(edit, STARTUP_ROLES[2])
    need(tuple(len(raw) for raw in (new_boot, new_owner, new_outer)) == (19583, 103959, 24060),
         'same_length_startup')
    fc_changes = [(old_fc['schema'], new_fc['schema'], 1, 'schema'),
                  ('"source_bytes": 99972', '"source_bytes": 100114', 1, 'source_bytes')]
    for old, new in zip(old_fc['sources'], new_fc['sources']):
        if old != new:
            fc_changes.append((json_record_text(old, '      '), json_record_text(new, '      '), 1,
                               'source.' + old['module']))
    fc_raw, proof = json_change(inputs[SOURCE_PINS[5][0]], fc_changes, new_fc, FC_MANIFEST, SOURCE_PINS[5][0])
    outputs[FC_MANIFEST] = fc_raw
    deltas.append(proof)
    new_catalog = json.loads(inputs[SOURCE_PINS[3][0]])
    new_catalog['schema'] = 'p011-formal-send-fc-http-cap-v1-ordinary-source-catalog'
    new_catalog['ordinary_root'], new_catalog['physical_ordinary_root'] = NEW_REMOTE + '/runtime', NEW_PHYSICAL + '/runtime'
    catalog_changes = [(old_catalog['schema'], new_catalog['schema'], 1, 'schema'),
                       (OLD_NAME, NEW_NAME, 76, 'independent_target_roots')]
    for group in ('sources', 'startup_sources', 'helper_sources'):
        for old, new in zip(old_catalog[group], new_catalog[group]):
            for key in ('target', 'physical_target'):
                new[key] = new[key].replace(OLD_NAME, NEW_NAME)
            if new.get('module') in new_roles:
                path, size, sha = new_roles[new['module']]
                new.update(source=path, bytes=size, sha256=sha)
                catalog_changes.append((json_record_text(old, '      '), json_record_text(new, '      '), 1,
                                        'source.' + new['module']))
    new_catalog['filecenter_source_manifest'] = dict(source=FC_MANIFEST, bytes=len(fc_raw), sha256=digest(fc_raw))
    catalog_changes.append((json_record_text(old_catalog['filecenter_source_manifest'], '    '),
                            json_record_text(new_catalog['filecenter_source_manifest'], '    '), 1, 'fc_manifest'))
    need(new_catalog['ordinary_source_bytes'] == sum(row['bytes'] for row in new_catalog['sources']) == 1078691 and
         sum(row[1] for row in ordinary_rows(new_catalog)) == 1368142 and len(ordinary_rows(new_catalog)) == 37 and
         new_catalog['separate_asset_catalog'] == old_catalog['separate_asset_catalog'], 'unchanged_batch_caps')
    catalog_raw, proof = json_change(inputs[SOURCE_PINS[3][0]], catalog_changes, new_catalog,
                                      ORDINARY_MANIFEST, SOURCE_PINS[3][0])
    outputs[ORDINARY_MANIFEST] = catalog_raw
    deltas.append(proof)
    edit = Edit(SOURCE_PINS[9][0], stage)
    edit.change(OLD_NAME, NEW_NAME, label='ordinary_profile_root')
    for name in ROOT_ROLES + STARTUP_ROLES:
        old = sources.get(name, startup.get(name))
        edit.hash_constant(old['sha256'], new_roles[name][2], 'PROFILE_FILES.' + name)
    new_stage = finish(edit, 'formal_send_stage')
    need(literal(new_stage, 'PROFILE_FILES') == old_profiles[:2] +
         (('ordinary', NEW_PHYSICAL, ordinary_rows(new_catalog)),) and
         literal(new_stage, 'PROFILE_TOTALS') == old_totals, 'new_stage_inventory')
    edit = Edit(SOURCE_PINS[11][0], guardian)
    edit.change(OLD_CONTROL_SUFFIX, NEW_CONTROL_SUFFIX, label='independent_control_name')
    new_guardian = finish(edit, 'ui_guardian')
    edit = Edit(SOURCE_PINS[12][0], worker)
    edit.change(OLD_NAME, NEW_NAME, 2, 'independent_sender_root')
    edit.change(OLD_CONTROL_SUFFIX, NEW_CONTROL_SUFFIX, label='independent_control_name')
    edit.pin_constant('SENDER_PIN', SOURCE_PINS[8][1:], new_roles[STARTUP_ROLES[2]][1:])
    edit.pin_constant('GUARDIAN_PIN', SOURCE_PINS[11][1:], new_roles['ui_guardian'][1:])
    replace_fc(edit, old_fc['sources'], new_fc['sources'])
    edit.change('sum(len(row[1]) for row in filecenter_sources) == 99972 and',
                'sum(len(row[1]) for row in filecenter_sources) == 100114 and', label='fixed_fc9_total_bytes')
    new_worker = finish(edit, 'ui_session', ('_validate_filecenter_sources',))
    target = ROOT + '/runtime/ui_assets.py'
    outputs[target] = validator
    new_roles['ui_assets'] = pin(target, validator)
    deltas.append(dict(source=list(SOURCE_PINS[10]), candidate=list(new_roles['ui_assets']),
                       identical_bytes=True, no_constant_change=True))
    need(literal(new_owner, 'FILECENTER_PINS') == literal(new_worker, 'FILECENTER_PINS') == fc_pins(new_fc['sources']) and
         literal(new_outer, 'OWNER_PIN') == new_roles['mta_client_service_owner'][1:] and
         literal(new_worker, 'SENDER_PIN') == new_roles['formal_send_session'][1:] and
         literal(new_worker, 'GUARDIAN_PIN') == new_roles['ui_guardian'][1:] and
         literal(new_worker, 'ASSETS_PIN') == new_roles['ui_assets'][1:] and
         literal(new_boot, 'SOURCE_PINS') == fc_pins(new_catalog['sources']), 'new_full_pin_closure')
    need(new_worker.count(b'filecenter_parent_deadline_verified=False') == worker.count(
         b'filecenter_parent_deadline_verified=False') == 1 and
         literal(new_owner, 'CLEANUP_SECONDS') == 60.0 and literal(new_boot, 'LOAD_SECONDS') == 10.0 and
         literal(new_outer, 'PROFILES') == literal(outer, 'PROFILES') and
         literal(new_stage, 'MAX_SECONDS') == literal(stage, 'MAX_SECONDS') and
         expression(new_stage, 'RAW_LIMIT') == expression(stage, 'RAW_LIMIT'), 'unchanged_protection_and_evidence')
    delta = dict(schema='p011-formal-send-fc-http-cap-v1-exactsource-delta',
        origin_owner=list(SOURCE_PINS[7]), origin_worker=list(SOURCE_PINS[12]),
        historical_v3_owner_not_loaded=True, source_records=deltas,
        filecenter_two_changed_sources=[list(FC_NEW[name]) for name in ('mta_toolbox_minhttp', 'mta_filecenter_companion')],
        filecenter_other_seven_source_records_unchanged=True, ordinary_methods_logic_unchanged=True,
        definition_constant_exceptions=['mta_client_service_owner._LinuxIo._anchors: root literal only',
                                        'ui_session._validate_filecenter_sources: FC9 total bytes only'],
        ui_payload_changed=False, assets_validator_identical=True,
        receive_family_successor_source_read_or_changed=False,
        no_runtime_definitions_executed=True, device=False, staged=False, host=False, rf=False, phone=False)
    outputs[DELTA] = encode(delta)
    facts = dict(schema='p011-formal-send-fc-http-cap-v1-generation',
        scope='PC_SOURCE_ONLY_NOT_STAGED_NOT_RUN', generator=list(pin(SELF, own_raw)),
        source_owner=list(SOURCE_PINS[7]), source_worker=list(SOURCE_PINS[12]),
        ordinary_manifest=list(pin(ORDINARY_MANIFEST, catalog_raw)), filecenter_manifest=list(pin(FC_MANIFEST, fc_raw)),
        ordinary_root=NEW_REMOTE, physical_ordinary_root=NEW_PHYSICAL,
        sender_outer=list(new_roles['formal_send_session']), worker=list(new_roles['ui_session']),
        guardian=list(new_roles['ui_guardian']), assets_validator=list(new_roles['ui_assets']),
        reused_gui_bundle=BUNDLE, reused_gui_session=SESSION, reused_gui_files=19, reused_gui_bytes=4185296,
        control_name='p011-mta-ui-session-' + SESSION + NEW_CONTROL_SUFFIX,
        control='/var/volatile/tmp/p011-mta-ui-session-' + SESSION + NEW_CONTROL_SUFFIX,
        filecenter_source_count=9, filecenter_source_bytes=100114, filecenter_source_cap=131072,
        ordinary_source_count=32, ordinary_source_bytes=1078691, ordinary_batch_files=37,
        ordinary_batch_bytes=1368142, unchanged_sender_assets=27, unchanged_observer_assets=41,
        original_boot_load_seconds=10, original_ui_window_seconds=600, original_cleanup_seconds=60,
        original_stage_seconds=120, original_wire_cap_bytes=4 * 1024 * 1024,
        exactsource_delta=list(pin(DELTA, outputs[DELTA])), input_count=len(inputs),
        inputs=[list(pin(path, raw)) for path, raw in sorted(inputs.items())],
        output_count=14, output_pins=[list(pin(path, raw)) for path, raw in sorted(outputs.items())],
        generation_output_not_self_pinned=True, old_generator_definitions_executed=0, old_mains=0, tests=0,
        business_definitions_executed=False, ui_changed=False, receive_changed=False, host_entry_connected=False,
        source_only_device_root_existence_not_observed=True, filecenter_parent_deadline_verified=False,
        whole_owner_closure_verified=False, restore_verified=False, real_mobile_transfer_verified=False,
        device=False, staged=False, runtime=False, host=False, native=False, rf=False, phone=False,
        failed_partial_outputs_preserved=True)
    outputs[GENERATION] = encode(facts)
    need(len(outputs) == facts['output_count'] == 14 and len(new_roles) == 10 and
         all(path.startswith(ROOT + '/') and path != SELF and type(raw) is bytes and 0 < len(raw) <= FILE_CAP
             for path, raw in outputs.items()), 'output_partition')
    preserve(inputs)
    return outputs, facts, inputs


def publish(outputs, inputs):
    """Precheck every existing target before any EXCL write; never overwrite."""
    need(os.name == 'nt' and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'explicit_local_pc_write')
    directories(BASE / ROOT)
    expected_files = {SELF} | set(outputs)
    allowed_dirs = {ROOT, ROOT + '/runtime', ROOT + '/assets'}
    for path in sorted(relative(ROOT).rglob('*')):
        name = path.relative_to(BASE).as_posix()
        value = path.lstat()
        need(not stat.S_ISLNK(value.st_mode) and not getattr(value, 'st_file_attributes', 0) & 0x400,
             'target_reparse')
        need(name in allowed_dirs if stat.S_ISDIR(value.st_mode) else name in expected_files, 'target_inventory')
    for name in (ROOT + '/runtime', ROOT + '/assets'):
        location = relative(name)
        if os.path.lexists(location):
            directories(location)
    for path, raw in outputs.items():
        if os.path.lexists(relative(path)):
            need(read(path, (len(raw), digest(raw))) == raw, 'existing_target_identical')
    preserve(inputs)
    for name in (ROOT + '/runtime', ROOT + '/assets'):
        location = relative(name)
        if not os.path.lexists(location):
            location.mkdir(exist_ok=False)
        directories(location)
    for path, raw in outputs.items():
        location = relative(path)
        if not os.path.lexists(location):
            with location.open('xb') as stream:
                need(stream.write(raw) == len(raw), 'exclusive_full_write')
                stream.flush()
                os.fsync(stream.fileno())
        need(read(path, (len(raw), digest(raw))) == raw, 'published_readback')
    observed = {path.relative_to(BASE).as_posix() for path in relative(ROOT).rglob('*') if path.is_file()}
    need(observed == expected_files, 'exact_final_inventory')
    preserve(inputs)


def main():
    need(sys.argv[1:] in ([], ['--write']), 'explicit_write_only')
    outputs, facts, inputs = prepare()
    if sys.argv[1:] == ['--write']:
        publish(outputs, inputs)
    print(json.dumps(dict(mode='EXCL_OR_IDENTICAL_PC_ONLY' if sys.argv[1:] else 'SOURCE_ONLY_NO_WRITES',
        generator=list(pin(SELF, inputs[SELF])), inputs=len(inputs), outputs=len(outputs),
        output_pins=[list(pin(path, raw)) for path, raw in sorted(outputs.items())],
        filecenter_source_bytes=facts['filecenter_source_bytes'], ordinary_root=NEW_REMOTE,
        device=False, staged=False, runtime=False, host=False, rf=False, phone=False), indent=2))


if __name__ == '__main__':
    main()
