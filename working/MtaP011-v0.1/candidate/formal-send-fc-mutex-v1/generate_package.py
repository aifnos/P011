"""Independent PC-only send package: actual HTTP-cap outputs plus media mutex.

prepare() returns (outputs, facts, inputs); it never runs an older recipe,
runtime definition, test, builder, Stage, UI, device, RF or phone entry. Only
the pinned send Companion changes in FC9. All other send/observer/GUI assets
remain exact. --write is EXCL-or-identical after a complete target precheck.
No receive successor is read or written; historical inputs stay immutable.
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
ROOT = 'candidate/formal-send-fc-mutex-v1'
SELF = ROOT + '/generate_package.py'
OLD = 'candidate/formal-send-fc-http-cap-v1'
OLD_NAME = 'p011-mta-formal-send-filecenter-httpcp-v1'
NEW_NAME = 'p011-mta-formal-send-filecenter-mutex1-v1'
OLD_REMOTE = '/tmp/' + OLD_NAME
NEW_REMOTE = '/tmp/' + NEW_NAME
OLD_PHYSICAL = '/var/volatile/tmp/' + OLD_NAME
NEW_PHYSICAL = '/var/volatile/tmp/' + NEW_NAME
OLD_CONTROL_SUFFIX = '-formal-send-fc-http-cap-v1'
NEW_CONTROL_SUFFIX = '-formal-send-fc-mutex-v1'
FC_MANIFEST = ROOT + '/assets/filecenter-source-manifest.json'
ORDINARY_MANIFEST = ROOT + '/assets/ordinary-source-manifest.json'
DELTA = ROOT + '/exactsource-delta.json'
GENERATION = ROOT + '/generation.json'
FILE_CAP = 2 * 1024 * 1024
SOURCE_PINS = (
    (OLD + '/generate_package.py', 33030,
     'd949a5d68efd0d4d29a47412feb99a61bed1c9e058716e02522678d7aad7b91d'),
    (OLD + '/generation.json', 27597,
     'a2bdae7d8e32c90e8f8926388fd1156c5c3169d1a41b0220f12895324ea33fb1'),
    (OLD + '/assets/ordinary-source-manifest.json', 20762,
     '6a478fc8bc8a61db8d43d1e89d10d1363c76fc3762fa51500dbe95539d794802'),
    (OLD + '/assets/filecenter-source-manifest.json', 2476,
     '819879157ba075d1afeb5bfad88e911408f5b060402166199c67b4b654a1d8a5'),
    ('candidate/filecenter-media-lock-deadline-v1/send/mta_filecenter_companion.py', 27656,
     '57531992acaf8b3519e090f8e1cf61a2ac97dc18e14bee15662573dbb9ca5bfd'),
    ('candidate/filecenter-media-lock-deadline-v1/send/exactsource-delta.json', 4751,
     '690bbf7a2d8e79529567e4eba34086ff498020a9167be51d3ee306c9f7e710a6'),
)
ROOT_ROLES = ('mta_send_trial', 'mta_send_terminal_consumer', 'mta_service')
STARTUP_ROLES = ('mta_client_receive_boot', 'mta_client_service_owner', 'formal_send_session')
RUNTIME_ROLES = ROOT_ROLES + STARTUP_ROLES + ('formal_send_stage', 'ui_guardian', 'ui_session', 'ui_assets')
COPIED_FUNCTIONS = (
    'need', 'digest', 'pin', 'encode', 'metadata', 'relative', 'directories', 'read', 'take',
    'preserve', 'parse', 'literal', 'expression', 'functions', 'functions.visit',
    'Edit.__init__', 'Edit.change', 'Edit.pin_constant', 'Edit.hash_constant', 'Edit.finish',
    'record', 'fc_pins', 'replace_fc', 'ordinary_rows', 'json_change', 'json_record_text', 'publish',
)


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


def prove_companion(inputs, old_row):
    old = inputs[old_row['source']]
    new = inputs[SOURCE_PINS[4][0]]
    delta = json.loads(inputs[SOURCE_PINS[5][0]])
    need(delta['schema'] == 'filecenter-media-lock-deadline-v1-exactsource-delta' and delta['side'] == 'send' and
         (delta['origin']['path'], delta['origin']['bytes'], delta['origin']['sha256']) == record(old_row) and
         (delta['candidate']['path'], delta['candidate']['bytes'], delta['candidate']['sha256']) == SOURCE_PINS[4] and
         len(delta['replacements']) == 8 and delta['blocking_file_io_preemption_verified'] is False and
         all(delta[key] is True for key in ('complete_byte_inverse', 'complete_ast_inverse',
             'all_other_definition_bytes_unchanged', 'close_method_bytes_unchanged',
             'original_guard_bytes_unchanged', 'parent_original_until_unchanged')), 'actual_send_mutex_delta')
    current = old
    for step in delta['replacements']:
        before, after = step['before'].encode('ascii'), step['after'].encode('ascii')
        need(step['count'] == 1 and current.count(before) == 1 and after not in current, 'fc_forward_anchor')
        current = current.replace(before, after, 1)
    need(current == new and len(new) - len(old) == 1568, 'actual_send_mutex_forward')
    for step in reversed(delta['replacements']):
        before, after = step['before'].encode('ascii'), step['after'].encode('ascii')
        need(current.count(after) == 1, 'fc_inverse_anchor')
        current = current.replace(after, before, 1)
    need(current == old and ast.dump(parse(current), include_attributes=True) ==
         ast.dump(parse(old), include_attributes=True), 'actual_send_mutex_full_inverse')
    original_defs, unused = functions(old)
    new_defs, unused = functions(new)
    need(set(new_defs) == set(original_defs) | set(delta['added_methods']) and
         tuple(name for name in original_defs if original_defs[name] != new_defs[name]) == tuple(delta['changed_methods']) and
         all(new_defs[name] == original_defs[name] for name in
             ('_Companion.close', '_Companion.closed', '_Companion.check', 'create')), 'fc_definition_scope')
    return delta


def prepare():
    """Read actual fixed prior outputs; assemble new bytes without publishing."""
    need(Path(__file__).resolve() == BASE / SELF and ROOT != OLD and len(OLD_NAME) == len(NEW_NAME) == 41 and
         OLD_NAME != NEW_NAME, 'independent_package')
    inputs = {}
    for row in SOURCE_PINS: take(inputs, row)
    own = relative(SELF)
    own_size = own.lstat().st_size
    need(0 < own_size <= 262144, 'generator_cap')
    own_raw = own.read_bytes()
    need(len(own_raw) == own_size, 'generator_length_stable')
    take(inputs, pin(SELF, own_raw))
    old_helpers, unused = functions(inputs[SOURCE_PINS[0][0]])
    own_helpers, unused = functions(own_raw)
    need(all(name in old_helpers and own_helpers.get(name) == old_helpers[name] for name in COPIED_FUNCTIONS),
         'copied_mechanical_helpers_exact')
    prior = json.loads(inputs[SOURCE_PINS[1][0]])
    need(prior['schema'] == 'p011-formal-send-fc-http-cap-v1-generation' and
         tuple(prior['generator']) == SOURCE_PINS[0] and prior['input_count'] == len(prior['inputs']) == 130 and
         prior['output_count'] == 14 and len(prior['output_pins']) == 13 and
         prior['generation_output_not_self_pinned'] is True and prior['filecenter_source_bytes'] == 100114 and
         prior['ordinary_batch_files'] == 37 and prior['ordinary_batch_bytes'] == 1368142 and
         all(prior[key] is False for key in ('business_definitions_executed', 'ui_changed', 'receive_changed',
             'device', 'staged', 'runtime', 'host', 'native', 'rf', 'phone')), 'actual_prior_package')
    need(len({row[0] for row in prior['inputs']}) == 130 and
         len({row[0] for row in prior['output_pins']}) == 13 and
         all(row[0].startswith(OLD + '/') and row[0] not in (SELF, OLD + '/generation.json')
             for row in prior['output_pins']), 'prior_partition')
    for row in prior['inputs'] + prior['output_pins']: take(inputs, tuple(row))
    expected_prior = {OLD + '/runtime/' + name + '.py' for name in RUNTIME_ROLES} | {
        SOURCE_PINS[2][0], SOURCE_PINS[3][0], OLD + '/exactsource-delta.json'}
    need({row[0] for row in prior['output_pins']} == expected_prior, 'actual_fourteen_outputs')
    old_catalog = json.loads(inputs[SOURCE_PINS[2][0]])
    old_fc = json.loads(inputs[SOURCE_PINS[3][0]])
    need(old_catalog['schema'] == 'p011-formal-send-fc-http-cap-v1-ordinary-source-catalog' and
         old_catalog['ordinary_root'] == OLD_REMOTE + '/runtime' and
         old_catalog['physical_ordinary_root'] == OLD_PHYSICAL + '/runtime' and
         old_catalog['source_count'] == len(old_catalog['sources']) == 32 and
         len(old_catalog['startup_sources']) == len(old_catalog['helper_sources']) == 3 and
         old_catalog['ordinary_source_bytes'] == sum(row['bytes'] for row in old_catalog['sources']) == 1078691 and
         old_catalog['ordinary_batch_files'] == 37 and old_catalog['ordinary_batch_bytes'] == 1368142 and
         old_catalog['original_boot_load_seconds'] == 10 and old_catalog['wire_cap_bytes'] == 4 * 1024 * 1024 and
         old_catalog['program_cap_bytes'] == old_catalog['original_per_source_cap_bytes'] == FILE_CAP and
         all(old_catalog[key] is False for key in ('runtime', 'host_graph_tested', 'native', 'rf', 'phone', 'production')),
         'actual_httpcap_catalog')
    need(record(old_catalog['filecenter_source_manifest']) == SOURCE_PINS[3] and
         old_catalog['filecenter_source_delivery'] == old_fc['delivery'] == 'separate-fixed-memory-nine-source-caller' and
         old_fc['schema'] == 'p011-formal-send-fc-http-cap-v1-filecenter-source' and
         old_fc['source_count'] == len(old_fc['sources']) == 9 and old_fc['source_bytes'] == 100114 and
         old_fc['source_cap'] == 131072 and old_fc['in_protocol_stage_payload'] is False and
         old_fc['parent_deadline_crop_integrated'] is True, 'same_fc_delivery')
    assets_row = record(old_catalog['separate_asset_catalog'])
    assets = json.loads(inputs[assets_row[0]])
    need(assets['sender_source_count'] == len(assets['sender_sources']) == 25 and
         assets['observer_source_count'] == len(assets['observer_sources']) == 41 and
         assets['observer_load_count'] == 38 and assets['sender_root'] != OLD_PHYSICAL and
         assets['observer_root'] != OLD_PHYSICAL, 'same_separate_assets')
    for row in (old_catalog['sources'] + old_catalog['startup_sources'] + old_catalog['helper_sources'] +
                old_fc['sources'] + assets['sender_sources'] + assets['observer_sources'] +
                [assets['wpa'], assets['sender_manifest']]):
        take(inputs, record(row))
    for key in ('sender_source_table', 'observer_source_table', 'original_observer_source_table'):
        take(inputs, tuple(assets[key]))
    prior_pins = {row[0]: tuple(row) for row in prior['output_pins']}
    startup = {row['module']: row for row in old_catalog['startup_sources']}
    sources = {row['module']: row for row in old_catalog['sources']}
    need(tuple(startup) == STARTUP_ROLES and len(sources) == 32, 'same_startup_inventory')
    for name in ROOT_ROLES + STARTUP_ROLES:
        row = sources.get(name, startup.get(name))
        need(record(row) == prior_pins[OLD + '/runtime/' + name + '.py'], 'actual_runtime_record')
    boot, owner, outer = (inputs[startup[name]['source']] for name in STARTUP_ROLES)
    stage, validator, guardian, worker = (inputs[OLD + '/runtime/' + name + '.py'] for name in
                                        ('formal_send_stage', 'ui_assets', 'ui_guardian', 'ui_session'))
    boot_pin, owner_pin, outer_pin = (record(startup[name])[1:] for name in STARTUP_ROLES)
    guardian_pin = prior_pins[OLD + '/runtime/ui_guardian.py'][1:]
    validator_pin = prior_pins[OLD + '/runtime/ui_assets.py'][1:]
    need(literal(boot, 'SOURCE_PINS') == fc_pins(old_catalog['sources']) and
         literal(owner, 'BOOT_PIN') == literal(outer, 'BOOT_PIN') == boot_pin and
         literal(outer, 'OWNER_PIN') == owner_pin and literal(worker, 'SENDER_PIN') == outer_pin and
         literal(worker, 'GUARDIAN_PIN') == guardian_pin and literal(worker, 'ASSETS_PIN') == validator_pin and
         literal(owner, 'FILECENTER_PINS') == literal(worker, 'FILECENTER_PINS') == fc_pins(old_fc['sources']),
         'actual_httpcap_pin_chain')
    need(literal(boot, 'LOAD_SECONDS') == 10.0 and literal(owner, 'CLEANUP_SECONDS') == 60.0 and
         literal(owner, 'FILECENTER_MAX_SOURCE') == 131072 and literal(stage, 'MAX_SECONDS') == 120.0 and
         expression(stage, 'RAW_LIMIT') == ast.dump(ast.parse('4 * 1024 * 1024', mode='eval').body,
                                                   include_attributes=False) and
         literal(outer, 'PROFILES') == (('diagnostic', 60.0, False), ('send-interactive-v1', 600.0, True)) and
         literal(worker, 'SENDER_ROOT') == OLD_REMOTE and literal(worker, 'SENDER_PHYSICAL_ROOT') == OLD_PHYSICAL,
         'unchanged_protection_constants')
    old_profiles, old_totals = literal(stage, 'PROFILE_FILES'), literal(stage, 'PROFILE_TOTALS')
    need(tuple(row[0] for row in old_profiles) == ('sender', 'observer', 'ordinary') and
         old_profiles[2] == ('ordinary', OLD_PHYSICAL, ordinary_rows(old_catalog)) and
         old_totals == (('sender', 27, 2402458), ('observer', 41, 1548495), ('ordinary', 37, 1368142)),
         'actual_stage_inventory')
    session = literal(validator, 'SESSION')
    bundle = prior['reused_gui_bundle']
    ui_pins, manifest_pin = literal(validator, 'PINS'), literal(validator, 'MANIFEST_PIN')
    need(session == literal(guardian, 'SESSION') == literal(worker, 'SESSION') == prior['reused_gui_session'] and
         bundle == 'out/mta-ui-send-status-v1-' + session and len(ui_pins) == 18 and tuple(sorted(ui_pins)) == ui_pins and
         prior['reused_gui_files'] == 19 and prior['reused_gui_bytes'] == 4185296, 'same_gui_identity')
    for name, size, sha in ui_pins + (('SOURCE.sha256',) + manifest_pin,):
        take(inputs, (bundle + '/' + name, size, sha))
    need(inputs[bundle + '/SOURCE.sha256'] == ''.join(sha + ' ' + str(size) + ' ' + name + '\n'
         for name, size, sha in ui_pins).encode('ascii') and
         sum(len(inputs[bundle + '/' + name]) for name, size, sha in
             ui_pins + (('SOURCE.sha256',) + manifest_pin,)) == 4185296, 'same_gui_byte_readback')
    changed_fc = [row for row in old_fc['sources'] if row['module'] == 'mta_filecenter_companion']
    need(len(changed_fc) == 1, 'unique_send_companion')
    business_delta = prove_companion(inputs, changed_fc[0])
    new_fc = json.loads(inputs[SOURCE_PINS[3][0]])
    for row in new_fc['sources']:
        if row['module'] == 'mta_filecenter_companion':
            row.update(source=SOURCE_PINS[4][0], bytes=SOURCE_PINS[4][1], sha256=SOURCE_PINS[4][2])
    new_fc['schema'] = 'p011-formal-send-fc-mutex-v1-filecenter-source'
    new_fc['source_bytes'] = sum(len(inputs[row['source']]) for row in new_fc['sources'])
    need(new_fc['source_bytes'] == 101682 and new_fc['source_bytes'] <= new_fc['source_cap'] and
         sum(old != new for old, new in zip(old_fc['sources'], new_fc['sources'])) == 1 and
         all(old == new for old, new in zip(old_fc['sources'], new_fc['sources'])
             if old['module'] != 'mta_filecenter_companion'), 'only_companion_changed_fc8_exact')
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
    edit = Edit(startup[STARTUP_ROLES[0]]['source'], boot)
    edit.change(OLD_NAME, NEW_NAME, 2, 'independent_ordinary_root')
    for name in ROOT_ROLES:
        edit.hash_constant(sources[name]['sha256'], new_roles[name][2], 'SOURCE_PINS.' + name)
    new_boot = finish(edit, STARTUP_ROLES[0])
    edit = Edit(startup[STARTUP_ROLES[1]]['source'], owner)
    edit.change(OLD_NAME, NEW_NAME, 2, 'independent_ordinary_root_and_anchor')
    edit.pin_constant('BOOT_PIN', boot_pin, new_roles[STARTUP_ROLES[0]][1:])
    replace_fc(edit, old_fc['sources'], new_fc['sources'])
    new_owner = finish(edit, STARTUP_ROLES[1], ('_LinuxIo._anchors',))
    edit = Edit(startup[STARTUP_ROLES[2]]['source'], outer)
    edit.change(OLD_NAME, NEW_NAME, 2, 'independent_ordinary_root')
    edit.pin_constant('BOOT_PIN', boot_pin, new_roles[STARTUP_ROLES[0]][1:])
    edit.pin_constant('OWNER_PIN', owner_pin, new_roles[STARTUP_ROLES[1]][1:])
    new_outer = finish(edit, STARTUP_ROLES[2])
    need(tuple(len(raw) for raw in (new_boot, new_owner, new_outer)) == (19583, 103959, 24060),
         'same_length_startup')
    fc_changes = [(old_fc['schema'], new_fc['schema'], 1, 'schema'),
                  ('"source_bytes": 100114', '"source_bytes": 101682', 1, 'source_bytes')]
    for old, new in zip(old_fc['sources'], new_fc['sources']):
        if old != new:
            fc_changes.append((json_record_text(old, '      '), json_record_text(new, '      '), 1,
                               'source.' + old['module']))
    fc_raw, proof = json_change(inputs[SOURCE_PINS[3][0]], fc_changes, new_fc, FC_MANIFEST, SOURCE_PINS[3][0])
    outputs[FC_MANIFEST] = fc_raw
    deltas.append(proof)
    new_catalog = json.loads(inputs[SOURCE_PINS[2][0]])
    new_catalog['schema'] = 'p011-formal-send-fc-mutex-v1-ordinary-source-catalog'
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
         new_catalog['separate_asset_catalog'] == old_catalog['separate_asset_catalog'] and
         new_catalog['separate_sender_manifest'] == old_catalog['separate_sender_manifest'], 'same_batch_caps')
    # Use actual source/output lengths for every ordinary inventory entry, not metadata alone.
    for group in ('sources', 'startup_sources', 'helper_sources'):
        for row in new_catalog[group]:
            raw = outputs.get(row['source'], inputs.get(row['source']))
            need(type(raw) is bytes and pin(row['source'], raw) == record(row), 'actual_ordinary_inventory_bytes')
    catalog_raw, proof = json_change(inputs[SOURCE_PINS[2][0]], catalog_changes, new_catalog,
                                      ORDINARY_MANIFEST, SOURCE_PINS[2][0])
    outputs[ORDINARY_MANIFEST] = catalog_raw
    deltas.append(proof)
    edit = Edit(OLD + '/runtime/formal_send_stage.py', stage)
    edit.change(OLD_NAME, NEW_NAME, label='ordinary_profile_root')
    for name in ROOT_ROLES + STARTUP_ROLES:
        old = sources.get(name, startup.get(name))
        edit.hash_constant(old['sha256'], new_roles[name][2], 'PROFILE_FILES.' + name)
    new_stage = finish(edit, 'formal_send_stage')
    need(literal(new_stage, 'PROFILE_FILES') == old_profiles[:2] +
         (('ordinary', NEW_PHYSICAL, ordinary_rows(new_catalog)),) and
         literal(new_stage, 'PROFILE_TOTALS') == old_totals and len(new_stage) == len(stage), 'new_stage_closed_inventory')
    edit = Edit(OLD + '/runtime/ui_guardian.py', guardian)
    edit.change(OLD_CONTROL_SUFFIX, NEW_CONTROL_SUFFIX, label='independent_control_name')
    new_guardian = finish(edit, 'ui_guardian')
    edit = Edit(OLD + '/runtime/ui_session.py', worker)
    edit.change(OLD_NAME, NEW_NAME, 2, 'independent_sender_root')
    edit.change(OLD_CONTROL_SUFFIX, NEW_CONTROL_SUFFIX, label='independent_control_name')
    edit.pin_constant('SENDER_PIN', outer_pin, new_roles[STARTUP_ROLES[2]][1:])
    edit.pin_constant('GUARDIAN_PIN', guardian_pin, new_roles['ui_guardian'][1:])
    replace_fc(edit, old_fc['sources'], new_fc['sources'])
    edit.change('sum(len(row[1]) for row in filecenter_sources) == 100114 and',
                'sum(len(row[1]) for row in filecenter_sources) == 101682 and', label='fixed_fc9_total_bytes')
    new_worker = finish(edit, 'ui_session', ('_validate_filecenter_sources',))
    target = ROOT + '/runtime/ui_assets.py'
    outputs[target] = validator
    new_roles['ui_assets'] = pin(target, validator)
    deltas.append(dict(source=list(prior_pins[OLD + '/runtime/ui_assets.py']), candidate=list(new_roles['ui_assets']),
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
         expression(new_stage, 'RAW_LIMIT') == expression(stage, 'RAW_LIMIT'), 'same_protection_evidence')
    delta = dict(schema='p011-formal-send-fc-mutex-v1-exactsource-delta',
        origin_package=list(SOURCE_PINS[1]), origin_recipe=list(SOURCE_PINS[0]),
        origin_owner=list(record(startup[STARTUP_ROLES[1]])), origin_worker=list(prior_pins[OLD + '/runtime/ui_session.py']),
        source_records=deltas, business_companion_source=list(SOURCE_PINS[4]),
        business_companion_exact_delta=list(SOURCE_PINS[5]), business_companion_replacements=business_delta['replacements'],
        filecenter_other_eight_source_records_unchanged=True, ordinary_methods_logic_unchanged=True,
        definition_constant_exceptions=['mta_client_service_owner._LinuxIo._anchors: root literal only',
                                        'ui_session._validate_filecenter_sources: FC9 total bytes only'],
        complete_companion_byte_ast_inverse=True, ui_payload_changed=False, assets_validator_identical=True,
        receive_successor_source_read_or_changed=False, original_caps_close_and_owner_identity_unchanged=True,
        no_runtime_definitions_executed=True, device=False, staged=False, host=False, rf=False, phone=False)
    outputs[DELTA] = encode(delta)
    facts = dict(schema='p011-formal-send-fc-mutex-v1-generation', scope='PC_SOURCE_ONLY_NOT_STAGED_NOT_RUN',
        generator=list(pin(SELF, own_raw)), mother_recipe=list(SOURCE_PINS[0]), mother_package=list(SOURCE_PINS[1]),
        source_owner=list(record(startup[STARTUP_ROLES[1]])), source_worker=list(prior_pins[OLD + '/runtime/ui_session.py']),
        ordinary_manifest=list(pin(ORDINARY_MANIFEST, catalog_raw)), filecenter_manifest=list(pin(FC_MANIFEST, fc_raw)),
        ordinary_root=NEW_REMOTE, physical_ordinary_root=NEW_PHYSICAL,
        sender_outer=list(new_roles['formal_send_session']), worker=list(new_roles['ui_session']),
        guardian=list(new_roles['ui_guardian']), assets_validator=list(new_roles['ui_assets']),
        reused_gui_bundle=bundle, reused_gui_session=session, reused_gui_files=19, reused_gui_bytes=4185296,
        control_name='p011-mta-ui-session-' + session + NEW_CONTROL_SUFFIX,
        control='/var/volatile/tmp/p011-mta-ui-session-' + session + NEW_CONTROL_SUFFIX,
        filecenter_source_count=9, filecenter_source_bytes=101682, filecenter_source_cap=131072,
        filecenter_companion_only_changed=True, filecenter_other_eight_exact=True,
        ordinary_source_count=32, ordinary_source_bytes=1078691, ordinary_batch_files=37,
        ordinary_batch_bytes=1368142, actual_ordinary_lengths_verified=True,
        unchanged_sender_assets=27, unchanged_observer_assets=41,
        original_boot_load_seconds=10, original_ui_window_seconds=600, original_cleanup_seconds=60,
        original_stage_seconds=120, original_wire_cap_bytes=4 * 1024 * 1024,
        exactsource_delta=list(pin(DELTA, outputs[DELTA])), input_count=len(inputs),
        inputs=[list(pin(path, raw)) for path, raw in sorted(inputs.items())],
        output_count=14, output_pins=[list(pin(path, raw)) for path, raw in sorted(outputs.items())],
        generation_output_not_self_pinned=True, copied_mechanical_helper_bytes_unchanged=True,
        old_prepare_verify_main_called=0, old_generator_definitions_executed=0, old_mains=0, tests=0,
        business_definitions_executed=False, ui_changed=False, receive_changed=False, host_entry_connected=False,
        source_only_device_root_existence_not_observed=True, filecenter_parent_deadline_verified=False,
        filecenter_media_mutex_device_verified=False, audio_shorter_callback_deadline_verified=False,
        blocking_file_io_preemption_verified=False, whole_owner_closure_verified=False,
        restore_verified=False, real_mobile_transfer_verified=False,
        device=False, staged=False, runtime=False, host=False, native=False, rf=False, phone=False,
        failed_partial_outputs_preserved=True)
    outputs[GENERATION] = encode(facts)
    need(len(outputs) == facts['output_count'] == 14 and set(new_roles) == set(RUNTIME_ROLES) and
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
        ordinary_batch_files=facts['ordinary_batch_files'], ordinary_batch_bytes=facts['ordinary_batch_bytes'],
        device=False, staged=False, runtime=False, host=False, rf=False, phone=False), indent=2))


if __name__ == '__main__':
    main()
