"""Independent PC-only receive mutex graph, derived from actual Startup20.

prepare() reads fixed sources and derives bytes only. No old prepare, verify,
main, test or runtime definition is called. Only named pure byte/AST inverse
helpers from the frozen definitions are loaded. Default CLI does not write.
--write preflights all destinations and uses EXCL or exact existing bytes.
FC9 is separate from the unchanged 75-role/4MiB payload. This is not device,
Stage, whole close, blocking-file-IO preemption or phone/RF acceptance.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-fc-mutex-graph-v1/'
RUNTIME = PREFIX + 'runtime/'
SELF = PREFIX + 'generate_graph.py'
DEFINITIONS = 'host/formal_receive_fc_mutex_v1_definitions.py'
MANIFEST_PATH = 'host/formal_receive_fc_mutex_v1_definition_manifest.json'
PRIVATE_MANIFEST_PATH = 'host/formal_receive_fc_mutex_v1_private_source_manifest.json'
SPEC_PATH = PREFIX + 'graph-exactsource-delta.json'
REPORT_PATH = PREFIX + 'graph-generation.json'
MOTHER = ('host/formal_receive_startup_20s_v1_definitions.py', 297239,
          '49a56e7e809f2f515ca66735a38adf68d162aea1697e8d6a17cd74d0f68c61ca')
GENERATOR_MOTHER = ('candidate/receive-startup-20s-graph-v1/generate_graph.py', 41819,
                    'e3b690ff769187c48d87448198371d8025ed8fcdd9ae78678f8e17cf56e338d8')
MUTEX_SOURCE = ('candidate/filecenter-media-lock-deadline-v1/receive/mta_filecenter_companion.py', 35198,
                '44c14589ef7b6a0af98c6a3446b3bd7539640f5b7fccc23c5c9677c705ae02ca')
MUTEX_DELTA = ('candidate/filecenter-media-lock-deadline-v1/receive/exactsource-delta.json', 4760,
               '8f5d938dd5aac90374b1cf8be999756e35ba645e11f362c8726ad24c388cea35')
MUTEX_GENERATOR = ('candidate/filecenter-media-lock-deadline-v1/generate_candidate.py', 10637,
                   'e7e2b8e4d82e2efc8bb5bca10f9415227f946a197976cd58b9c9c26b0ad0059b')
ROOT_BEFORE = 'p011-mta-rx-prep20-v001'
ROOT_AFTER = 'p011-mta-rx-mlock1-v001'
PAYLOAD_BYTES = 4193768
PAYLOAD_CAP = 4194304
FILECENTER_BYTES = 115400
FILECENTER_CAP = 131072
CHANGED = ('mta_client_executor', 'mta_client_receive_factory', 'mta_client_state_bridge',
           'mta_client_receive_boot', 'mta_client_service_owner')
CHANGED_PAYLOAD_ROLES = CHANGED + ('runtime35/mta_client_executor',)
PURE_NAMES = ('need', 'digest', 'jraw', 'literal_assignment', 'replay', 'definition_rows',
              'validate_delta', 'validate_runner', 'owner_context', 'scope_originals',
              'validate_owner_business', 'validate_scope_business', 'validate_fc_http_delta',
              'cache_target', 'remove_cache_assignments', 'profile_method',
              'validate_profile_business', 'validate_prepare20_business', 'validate_manifest_inverse')
CURRENT_NAMES = (
    'ORIGIN_SOURCE_PINS', 'MANIFEST', 'PRIVATE_MANIFEST', 'RUNNER', 'GENERATION', 'GENERATION_EXPECTED',
    'DELTA_SPEC', 'DELTA_EXPECTED', 'ROOT_AFTER', 'ORDINARY_ROWS', 'PRIVATE_ROWS', 'HELPERS', 'WPA', 'MONITOR',
    'FILECENTER_SOURCES', 'PAYLOAD_BYTES', 'FILECENTER_BYTES', 'OLD_MANIFEST', 'ORIGINAL_MANIFEST_RAW',
    'OLD_PRIVATE_MANIFEST', 'OLD_PRIVATE_RAW', 'MOTHER_MECHANICAL_EXPECTED', 'MECHANICAL_EXPECTED',
    'MOTHER_MANIFEST_EXPECTED', 'MANIFEST_EXPECTED', 'MOTHER_DELTA', 'MOTHER_DELTA_EXPECTED',
    'MOTHER_GENERATION', 'MOTHER_GENERATION_EXPECTED', 'MOTHER_OUTPUT_PINS',
    'MOTHER_ORDINARY_ROWS', 'MOTHER_PRIVATE_ROWS', 'MOTHER_PAYLOAD_BYTES', 'ORIGINAL_PAYLOAD_ROWS',
    'CHANGED_PAYLOAD_ROLES', 'OWNER_BUSINESS_EXPECTED', 'SCOPE_BUSINESS_EXPECTED', 'FC_HTTP_EXPECTED',
    'CACHE_BUSINESS_EXPECTED', 'BUSINESS_EXPECTED', 'BUSINESS_CLOSURE_COUNT', 'CACHE_BYTE_CAP', 'FC_CHANGED')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, raw):
    return path, len(raw), digest(raw)


def jraw(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def scoped(name, missing=False):
    need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./-]+', name) is not None and
         not name.startswith('/') and all(part not in ('', '.', '..') for part in name.split('/')),
         'fixed_relative_path')
    target = BASE
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        need(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
             not getattr(value, 'st_file_attributes', 0) & 0x400, 'fixed_base')
    for index, part in enumerate(name.split('/')):
        target = target / part
        try:
            value = target.lstat()
        except FileNotFoundError:
            need(missing, 'missing_source')
            continue
        need(not stat.S_ISLNK(value.st_mode) and not getattr(value, 'st_file_attributes', 0) & 0x400,
             'path_reparse')
        if index < len(name.split('/')) - 1:
            need(stat.S_ISDIR(value.st_mode), 'path_ancestor')
    need(target.resolve().is_relative_to(BASE.resolve()), 'path_scope')
    return target


def read_pin(row):
    need(type(row) is tuple and len(row) == 3 and type(row[1]) is int and 0 < row[1] <= 2097152 and
         type(row[2]) is str and re.fullmatch('[0-9a-f]{64}', row[2]) is not None, 'input_pin_shape')
    target = scoped(row[0])
    before = target.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == row[1], 'source_regular')
    metadata = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    with target.open('rb') as handle:
        opened = os.fstat(handle.fileno())
        need(metadata(opened) == metadata(before), 'source_open_identity')
        raw = handle.read(row[1] + 1)
        need(metadata(os.fstat(handle.fileno())) == metadata(opened), 'source_held_changed')
    need(metadata(target.lstat()) == metadata(before) and (len(raw), digest(raw)) == row[1:], 'source_pin')
    return raw


def take(inputs, row):
    raw = read_pin(tuple(row))
    need(row[0] not in inputs or inputs[row[0]] == raw, 'input_collision')
    inputs[row[0]] = raw
    return raw


def parse(raw):
    return ast.parse(raw.decode('ascii'))


def assignment_node(raw, name):
    rows = [node for node in parse(raw).body if isinstance(node, ast.Assign) and len(node.targets) == 1 and
            isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(rows) == 1, 'unique_assignment:' + name)
    return rows[0]


def literal_assignment(raw, name):
    return ast.literal_eval(assignment_node(raw, name).value)


def span(raw, node):
    return b''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def source_function(raw, name):
    rows = [node for node in parse(raw).body if isinstance(node, ast.FunctionDef) and node.name == name]
    need(len(rows) == 1, 'unique_pure_function:' + name)
    return span(raw, rows[0]).decode('ascii').rstrip('\n')


def pure_current(raw):
    selected = [node for node in parse(raw).body if isinstance(node, ast.FunctionDef) and node.name in PURE_NAMES]
    need({node.name for node in selected} == set(PURE_NAMES) and len(selected) == len(PURE_NAMES), 'pure_inventory')
    module = types.ModuleType('_receive_fc_mutex_current_pure_inverses')
    module.__dict__.update(ast=ast, copy=copy, hashlib=hashlib, json=json, ROOT_AFTER=ROOT_BEFORE,
                           CACHE_BYTE_CAP=literal_assignment(raw, 'CACHE_BYTE_CAP'),
                           FC_CHANGED=literal_assignment(raw, 'FC_CHANGED'))
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<current-pure-inverses>', 'exec'), module.__dict__)
    need(all(name not in module.__dict__ for name in ('prepare', 'verify_inputs', 'main')), 'old_entries_excluded')
    return module


def mutex_method_bytes(raw):
    lines, values = raw.splitlines(keepends=True), {}
    def walk(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.ClassDef, ast.FunctionDef)):
                name = '.'.join(prefix + (child.name,))
                if isinstance(child, ast.FunctionDef):
                    need(name not in values, 'mutex_definition_unique')
                    values[name] = b''.join(lines[child.lineno - 1:child.end_lineno])
                walk(child, prefix + (child.name,))
            else:
                walk(child, prefix)
    walk(ast.parse(raw.decode('utf-8'), feature_version=(3, 5)), ())
    return values


def validate_mutex(inputs, entry):
    before, after = inputs[entry['source'][0]], inputs[entry['candidate'][0]]
    need((len(before), digest(before)) == tuple(entry['source'][1:]) and
         (len(after), digest(after)) == tuple(entry['candidate'][1:]) and len(after) - len(before) == 1568,
         'mutex_actual_business_pins')
    delta = json.loads(inputs[entry['delta'][0]].decode('ascii'))
    need(delta == entry['delta_expected'] and delta['schema'] == 'filecenter-media-lock-deadline-v1-exactsource-delta' and
         delta['side'] == 'receive' and delta['origin'] == dict(path=entry['source'][0], bytes=entry['source'][1],
         sha256=entry['source'][2]) and delta['candidate'] == dict(path=entry['candidate'][0], bytes=entry['candidate'][1],
         sha256=entry['candidate'][2]), 'mutex_actual_delta')
    edits, forward, inverse = delta['replacements'], before, after
    need(type(edits) is list and len(edits) == 8 and all(row['count'] == 1 for row in edits), 'mutex_exact_eight')
    for row in edits:
        old, new = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(old and new and forward.count(old) == 1, 'mutex_forward_anchor')
        forward = forward.replace(old, new, 1)
    for row in reversed(edits):
        old, new = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(inverse.count(new) == 1, 'mutex_inverse_anchor')
        inverse = inverse.replace(new, old, 1)
    need(forward == after and inverse == before and ast.dump(ast.parse(inverse.decode('utf-8')), include_attributes=True) ==
         ast.dump(ast.parse(before.decode('utf-8')), include_attributes=True), 'mutex_complete_byte_ast_inverse')
    methods = ('_FileCenterHandler.dispatch', '_FileCenterHandler.media', '_Companion.open_file',
               '_Companion.media_row', '_Companion.audio_source_fd')
    added = ('_MediaLock.__init__', '_MediaLock.__enter__', '_MediaLock.__exit__')
    original, current = mutex_method_bytes(before), mutex_method_bytes(after)
    need(tuple(delta['changed_methods']) == methods and tuple(delta['added_methods']) == added and
         set(current) == set(original) | set(added) and
         {name for name in original if original[name] != current[name]} == set(methods), 'mutex_exact_method_scope')
    need(all(original[name] == current[name] for name in
         ('create', '_owner_binding', '_Companion.check', '_Companion.close', '_Companion.closed')),
         'mutex_original_authority_close_exact')
    helper = literal_assignment(inputs[entry['generator'][0]], 'HELPER')
    classes = [node for node in ast.parse(after.decode('utf-8')).body if isinstance(node, ast.ClassDef) and
               node.name == '_MediaLock']
    need(len(classes) == 1 and ast.dump(classes[0], include_attributes=False) ==
         ast.dump(ast.parse(helper.decode('ascii')).body[0], include_attributes=False), 'mutex_exact_frozen_helper')
    need(b'with self.media_lock:' not in after and b"with row['lock']:" not in after and
         delta['blocking_file_io_preemption_verified'] is False and delta['device_verified'] is False,
         'mutex_lock_only_not_device_or_io_preemption')


def validate_current(inputs, current):
    """Retained current closure using pure inverses, never its old verify entry."""
    for path, size, sha in current['ORIGIN_SOURCE_PINS']:
        need(path in inputs and (len(inputs[path]), digest(inputs[path])) == (size, sha), 'current_flat304_pin')
    need(len(current['ORIGIN_SOURCE_PINS']) == 304 and current['ROOT_AFTER'] == 'p011-mta-rx-prep20-v001' and
         current['PAYLOAD_BYTES'] == 4193768 and current['FILECENTER_BYTES'] == 113832 and
         current['BUSINESS_CLOSURE_COUNT'] == 1, 'current_prepare20_scope')
    need(inputs[current['OLD_MANIFEST'][0]] == current['ORIGINAL_MANIFEST_RAW'] and
         inputs[current['OLD_PRIVATE_MANIFEST'][0]] == current['OLD_PRIVATE_RAW'] and
         json.loads(inputs[current['DELTA_SPEC'][0]].decode('ascii')) == current['DELTA_EXPECTED'] and
         json.loads(inputs[current['GENERATION'][0]].decode('ascii')) == current['GENERATION_EXPECTED'],
         'current_original_metadata_exact')
    validate_owner_business(inputs, current['OWNER_BUSINESS_EXPECTED'])
    validate_scope_business(inputs, current['SCOPE_BUSINESS_EXPECTED'])
    validate_fc_http_delta(inputs, current['FC_HTTP_EXPECTED'])
    validate_profile_business(inputs, current['CACHE_BUSINESS_EXPECTED'])
    validate_prepare20_business(inputs, current['BUSINESS_EXPECTED'])
    for entry in current['MOTHER_MECHANICAL_EXPECTED'] + current['MECHANICAL_EXPECTED']:
        before, after = inputs[entry['source'][0]], inputs[entry['candidate'][0]]
        validate_delta(before, after, entry['edits'], entry['functions_unchanged'])
        need(len(before) == len(after), 'current_equal_length_mechanical')
    validate_manifest_inverse(inputs, current['MOTHER_MANIFEST_EXPECTED'] + current['MANIFEST_EXPECTED'])
    need(json.loads(inputs[current['MOTHER_DELTA'][0]].decode('ascii')) == current['MOTHER_DELTA_EXPECTED'] and
         json.loads(inputs[current['MOTHER_GENERATION'][0]].decode('ascii')) == current['MOTHER_GENERATION_EXPECTED'] and
         tuple(tuple(row) for row in current['MOTHER_GENERATION_EXPECTED']['output_pins']) ==
         current['MOTHER_OUTPUT_PINS'][:9], 'current_inherited_graph_metadata')
    baseline = current['MOTHER_ORDINARY_ROWS'] + current['HELPERS'] + current['MOTHER_PRIVATE_ROWS'] + \
        (current['WPA'], current['MONITOR'])
    need(len(baseline) == 75 and sum(row[2] for row in baseline) == current['MOTHER_PAYLOAD_BYTES'], 'current_baseline75')
    payload = current['ORDINARY_ROWS'] + current['HELPERS'] + current['PRIVATE_ROWS'] + \
        (current['WPA'], current['MONITOR'])
    need(len(payload) == len({row[0] for row in payload}) == 75 and sum(row[2] for row in payload) == 4193768,
         'current_actual75_budget')
    for row in baseline + payload:
        need((len(inputs[row[1]]), digest(inputs[row[1]])) == row[2:], 'current_actual_payload_pin')
    changed = []
    for row, old in zip(payload, current['ORIGINAL_PAYLOAD_ROWS']):
        need(row[0] == old[0], 'current_payload_order')
        if row[0] in current['CHANGED_PAYLOAD_ROLES']:
            need(row != old, 'current_changed_role')
            changed.append(row[0])
        else:
            need(row == old and inputs[row[1]] == inputs[old[1]], 'current69_exact')
    need(tuple(changed) == current['CHANGED_PAYLOAD_ROLES'], 'current_six_changed_payload')
    ordinary = json.loads(inputs[current['MANIFEST'][0]].decode('ascii'))
    private = json.loads(inputs[current['PRIVATE_MANIFEST'][0]].decode('ascii'))
    need(tuple((row['module'], row['path'], row['bytes'], row['sha256']) for row in ordinary['sources']) ==
         current['ORDINARY_ROWS'] and tuple(('runtime35/' + row['module'], row['path'], row['bytes'], row['sha256'])
         for row in private['sources']) == current['PRIVATE_ROWS'], 'current_manifest_payload_exact')
    runner = inputs[current['RUNNER'][0]]
    need(literal_assignment(runner, 'STATE_ROOT') == '/var/volatile/tmp/' + current['ROOT_AFTER'] and
         literal_assignment(runner, 'STATE_ALIAS') == '/tmp/' + current['ROOT_AFTER'] and
         literal_assignment(runner, 'ROLE_PINS') == tuple((n, size, sha) for n, p, size, sha in current['ORDINARY_ROWS']) and
         literal_assignment(runner, 'PRIVATE_PINS') == tuple((n[10:], size, sha) for n, p, size, sha in current['PRIVATE_ROWS']) and
         literal_assignment(runner, 'HELPER_PINS') == tuple((n, size, sha) for n, p, size, sha in current['HELPERS']) and
         literal_assignment(runner, 'WPA_PIN') == (current['WPA'][0], current['WPA'][2], current['WPA'][3]) and
         literal_assignment(runner, 'MONITOR_PIN') == (current['MONITOR'][0], current['MONITOR'][2], current['MONITOR'][3]),
         'current_runner_full75')
    fc = current['FILECENTER_SOURCES']
    need(len(fc) == 9 and sum(row[2] for row in fc) == 113832, 'current_fc9_budget')
    for name, path, size, sha in fc:
        need((len(inputs[path]), digest(inputs[path])) == (size, sha), 'current_fc9_actual')
    owner = next(row for row in current['ORDINARY_ROWS'] if row[0] == 'mta_client_service_owner')
    previous_owner = next(row for row in current['MOTHER_ORDINARY_ROWS'] if row[0] == owner[0])
    factory = next(row for row in current['ORDINARY_ROWS'] if row[0] == 'mta_client_receive_factory')
    need(literal_assignment(inputs[owner[1]], 'FILECENTER_PINS') == tuple((n, size, sha) for n, p, size, sha in fc) and
         owner_context(inputs[owner[1]]) == owner_context(inputs[previous_owner[1]]) and
         literal_assignment(inputs[factory[1]], 'STARTUP_READ_SECONDS') == 20.0 and
         profile_method(inputs[factory[1]]) == profile_method(inputs[current['BUSINESS_EXPECTED']['candidate'][0]]) and
         profile_method(inputs[factory[1]]) == profile_method(inputs[current['MOTHER_OUTPUT_PINS'][3][0]]),
         'current_owner_context_prepare20_cache_exact')


def verify_inputs(inputs):
    """New mutex validator; retained prepare20 and new mutex counts are distinct."""
    for path, size, sha in ORIGIN_SOURCE_PINS:
        need(path in inputs and (len(inputs[path]), digest(inputs[path])) == (size, sha), 'mutex_flat_pin')
    validate_current(inputs, CURRENT_EXPECTED)
    validate_mutex(inputs, MUTEX_EXPECTED)
    need(BUSINESS_CLOSURE_COUNT == 1 and MUTEX_BUSINESS_CLOSURE_COUNT == 1 and
         BUSINESS_EXPECTED == CURRENT_EXPECTED['BUSINESS_EXPECTED'], 'distinct_prepare20_and_mutex_counts')
    need(inputs[OLD_MANIFEST[0]] == ORIGINAL_MANIFEST_RAW and inputs[OLD_PRIVATE_MANIFEST[0]] == OLD_PRIVATE_RAW and
         json.loads(inputs[DELTA_SPEC[0]].decode('ascii')) == DELTA_EXPECTED, 'mutex_parent_and_delta_exact')
    for entry in MECHANICAL_EXPECTED:
        before, after = inputs[entry['source'][0]], inputs[entry['candidate'][0]]
        validate_delta(before, after, entry['edits'], entry['functions_unchanged'])
        need(len(before) == len(after), 'mutex_equal_length_mechanical')
    validate_manifest_inverse(inputs, MANIFEST_EXPECTED)
    payload = manifest_rows(inputs[MANIFEST[0]]) + HELPERS + manifest_rows(inputs[PRIVATE_MANIFEST[0]], True) + (WPA, MONITOR)
    need(len(payload) == len({row[0] for row in payload}) == 75 and sum(row[2] for row in payload) ==
         PAYLOAD_BYTES == 4193768 <= PAYLOAD_CAP == 4194304, 'mutex75_unchanged_budget')
    changed = []
    for row, old in zip(payload, ORIGINAL_PAYLOAD_ROWS):
        need(row[0] == old[0] and (len(inputs[row[1]]), digest(inputs[row[1]])) == row[2:], 'mutex75_actual')
        if row[0] in CHANGED_PAYLOAD_ROLES:
            need(row != old, 'mutex_changed_payload')
            changed.append(row[0])
        else:
            need(row == old and inputs[row[1]] == inputs[old[1]], 'mutex69_original_payload')
    need(tuple(changed) == CHANGED_PAYLOAD_ROLES and MECHANICAL_CLOSURE_COUNT == 6, 'mutex_six_mechanical')
    validate_runner(inputs[RUNNER[0]], ORDINARY_ROWS, PRIVATE_ROWS, HELPERS, WPA, MONITOR)
    need(FILECENTER_SOURCE_PINS == FILECENTER_SOURCES and len(FILECENTER_SOURCES) == 9 and
         sum(row[2] for row in FILECENTER_SOURCES) == FILECENTER_BYTES == 115400 <= FILECENTER_CAP == 131072,
         'mutex_separate_fc9_budget')
    changed_fc = []
    for row, old in zip(FILECENTER_SOURCES, ORIGINAL_FILECENTER_ROWS):
        need(row[0] == old[0] and (len(inputs[row[1]]), digest(inputs[row[1]])) == row[2:], 'mutex_fc9_actual')
        if row[0] == 'mta_filecenter_companion':
            need(row[1:] == tuple(MUTEX_EXPECTED['candidate']) and row != old and
                 old[1:] == tuple(MUTEX_EXPECTED['source']), 'mutex_exact_companion_binding')
            changed_fc.append(row[0])
        else:
            need(row == old and inputs[row[1]] == inputs[old[1]], 'mutex_fc8_exact')
    need(changed_fc == ['mta_filecenter_companion'], 'mutex_only_one_fc_role')
    owner = next(row for row in ORDINARY_ROWS if row[0] == 'mta_client_service_owner')
    original_owner = next(row for row in CURRENT_EXPECTED['ORDINARY_ROWS'] if row[0] == owner[0])
    factory = next(row for row in ORDINARY_ROWS if row[0] == 'mta_client_receive_factory')
    original_factory = next(row for row in CURRENT_EXPECTED['ORDINARY_ROWS'] if row[0] == factory[0])
    need(literal_assignment(inputs[owner[1]], 'FILECENTER_PINS') ==
         tuple((n, size, sha) for n, p, size, sha in FILECENTER_SOURCES) and
         owner_context(inputs[owner[1]]) == owner_context(inputs[original_owner[1]]) and
         literal_assignment(inputs[factory[1]], 'STARTUP_READ_SECONDS') == 20.0 and
         profile_method(inputs[factory[1]]) == profile_method(inputs[original_factory[1]]),
         'mutex_original_owner_prepare20_cache')
    need(json.loads(inputs[GENERATION[0]].decode('ascii')) == GENERATION_EXPECTED, 'mutex_generation_exact')
    return MECHANICAL_CLOSURE_COUNT


def assignment(name, before, after):
    return dict(name=name + '_constant', before=name + ' = ' + repr(before) + '\n',
                after=name + ' = ' + repr(after) + '\n', count=1)


def source_tuple(name, before, after, count=1):
    return dict(name=name + '_tuple', before='    ' + repr((name,) + before[1:]) + ',\n',
                after='    ' + repr((name,) + after[1:]) + ',\n', count=count)


def derive_definitions(mother, constants, own):
    """Finite complete PC byte/AST inverse; all inherited public functions kept."""
    raw, ledger = mother, []
    def change(before, after):
        nonlocal raw
        need(raw.count(before) == 1 and before != after, 'definitions_forward_anchor')
        offset = raw.index(before)
        raw = raw[:offset] + after + raw[offset + len(before):]
        ledger.append((offset, before, after))
    for name, value in constants.items():
        if name not in ('CURRENT_EXPECTED', 'MUTEX_EXPECTED', 'MUTEX_BUSINESS_CLOSURE_COUNT'):
            node = assignment_node(raw, name)
            before = span(raw, node)
            after = (name + ' = ' + repr(value) + '\n').encode('ascii')
            if before != after:
                change(before, after)
    extra = ''.join(name + ' = ' + repr(constants[name]) + '\n' for name in
                    ('CURRENT_EXPECTED', 'MUTEX_EXPECTED', 'MUTEX_BUSINESS_CLOSURE_COUNT')).encode('ascii')
    change(b'\ndef need(value, code):\n', b'\n' + extra + b'\ndef need(value, code):\n')
    current_verify = [node for node in parse(raw).body if isinstance(node, ast.FunctionDef) and node.name == 'verify_inputs']
    need(len(current_verify) == 1, 'one_old_validator_replaced')
    replacement = ('\n\n'.join(source_function(own, name) for name in
                   ('mutex_method_bytes', 'validate_mutex', 'validate_current', 'verify_inputs')) + '\n').encode('ascii')
    change(span(raw, current_verify[0]), replacement)
    inverse = raw
    for offset, before, after in reversed(ledger):
        need(inverse[offset:offset + len(after)] == after, 'definitions_inverse_anchor')
        inverse = inverse[:offset] + before + inverse[offset + len(after):]
    need(inverse == mother and ast.dump(parse(inverse), include_attributes=True) ==
         ast.dump(parse(mother), include_attributes=True), 'definitions_complete_byte_position_ast_inverse')
    old_names = [node.name for node in parse(mother).body if isinstance(node, ast.FunctionDef)]
    new_names = [node.name for node in parse(raw).body if isinstance(node, ast.FunctionDef)]
    need(set(new_names) == set(old_names) | {'mutex_method_bytes', 'validate_mutex', 'validate_current'} and
         len(new_names) == len(old_names) + 3, 'definitions_function_inventory')
    for name in old_names:
        if name != 'verify_inputs':
            need(source_function(raw, name) == source_function(mother, name), 'inherited_public_function_byte_exact')
    need(len(raw) <= 2097152, 'definitions_pc_source_cap')
    return raw, dict(complete_byte_inverse=True, complete_position_ast_inverse=True,
        inherited_public_function_bytes_unchanged=True, old_verify_not_called=True,
        new_mutex_validator_separate=True, finite_pc_edits=len(ledger), bytes=len(raw), sha256=digest(raw))


def prepare():
    """Read fixed actual sources and derive new bytes; never call old entrypoints."""
    need(len(ROOT_BEFORE) == len(ROOT_AFTER) and
         Path(__file__).resolve() == scoped(SELF).resolve(), 'fixed_equal_length_recipe')
    inputs = {}
    mother = take(inputs, MOTHER)
    take(inputs, GENERATOR_MOTHER)
    current = {name: literal_assignment(mother, name) for name in CURRENT_NAMES}
    need(type(current['ORIGIN_SOURCE_PINS']) is tuple and len(current['ORIGIN_SOURCE_PINS']) == 304,
         'actual_startup20_flat304')
    for row in current['ORIGIN_SOURCE_PINS'] + (MUTEX_SOURCE, MUTEX_DELTA, MUTEX_GENERATOR):
        take(inputs, row)
    own_size = scoped(SELF).stat().st_size
    own_raw = scoped(SELF).read_bytes()
    need(len(own_raw) == own_size, 'recipe_initial_read')
    own = take(inputs, pin(SELF, own_raw))
    helpers = pure_current(mother)
    for name in ('mutex_method_bytes', 'validate_mutex', 'validate_current'):
        exec(compile(source_function(own, name), '<new-mutex-pure-' + name + '>', 'exec'), helpers.__dict__)
    helpers.validate_current(inputs, current)
    original_fc = current['FILECENTER_SOURCES']
    original_companion = next(row for row in original_fc if row[0] == 'mta_filecenter_companion')
    mutex = dict(source=list(original_companion[1:]), candidate=list(MUTEX_SOURCE),
                 delta=list(MUTEX_DELTA), generator=list(MUTEX_GENERATOR),
                 delta_expected=json.loads(inputs[MUTEX_DELTA[0]].decode('ascii')))
    helpers.validate_mutex(inputs, mutex)
    fc_rows = tuple((row[0],) + MUTEX_SOURCE if row[0] == 'mta_filecenter_companion' else row
                    for row in original_fc)
    need(len(fc_rows) == 9 and sum(row[2] for row in fc_rows) == FILECENTER_BYTES and
         tuple(row[0] for row, old in zip(fc_rows, original_fc) if row != old) == ('mta_filecenter_companion',),
         'one_mutex_fc9_independent_budget')
    old_manifest, old_private, old_runner = current['MANIFEST'], current['PRIVATE_MANIFEST'], current['RUNNER']
    ordinary, private = (json.loads(inputs[row[0]].decode('ascii')) for row in (old_manifest, old_private))
    need(jraw(ordinary) == inputs[old_manifest[0]] and jraw(private) == inputs[old_private[0]],
         'current_manifest_canonical')
    old_rows = {row['module']: (row['path'], row['bytes'], row['sha256']) for row in ordinary['sources']}
    original_payload = current['ORDINARY_ROWS'] + current['HELPERS'] + current['PRIVATE_ROWS'] + \
        (current['WPA'], current['MONITOR'])
    need(len(old_rows) == 35 and len(current['PRIVATE_ROWS']) == 35 and len(original_payload) == 75 and
         sum(row[2] for row in original_payload) == PAYLOAD_BYTES and
         not any(row[0] == 'mta_filecenter_companion' for row in original_payload), 'current75_not_fc9')
    outputs, mechanical, new_pins = {}, [], {}

    def create(name, source, edits, functions_unchanged=False):
        before = inputs[source[0]]
        raw = helpers.replay(before, edits)
        helpers.validate_delta(before, raw, edits, functions_unchanged)
        need(len(raw) == len(before), 'mechanical_equal_length:' + name)
        path = RUNTIME + name + '.py'
        outputs[path], new_pins[name] = raw, pin(path, raw)
        mechanical.append(dict(name=name, source=list(source), candidate=list(new_pins[name]),
                               edits=edits, functions_unchanged=functions_unchanged))

    def root(name, physical=False):
        prefix = '/var/volatile/tmp/' if physical else '/tmp/'
        return assignment(name, prefix + ROOT_BEFORE, prefix + ROOT_AFTER)

    create('mta_client_executor', old_rows['mta_client_executor'], [dict(name='private_runtime_root',
        before="    if (directory != '/var/volatile/tmp/" + ROOT_BEFORE + "/runtime35' and\n",
        after="    if (directory != '/var/volatile/tmp/" + ROOT_AFTER + "/runtime35' and\n", count=1)])
    executor = new_pins['mta_client_executor']
    create('mta_client_state_bridge', old_rows['mta_client_state_bridge'],
           [assignment('PARENT_SOURCE_SHA', old_rows['mta_client_executor'][2], executor[2])], True)
    private_new = copy.deepcopy(private)
    private_index = next(i for i, row in enumerate(private_new['sources']) if row['module'] == 'mta_client_executor')
    private_new['sources'][private_index] = dict(module='mta_client_executor', path=executor[0],
                                                bytes=executor[1], sha256=executor[2])
    private_new['previous_manifest_sha256'] = old_private[2]
    outputs[PRIVATE_MANIFEST_PATH] = jraw(private_new)
    private_pin = pin(PRIVATE_MANIFEST_PATH, outputs[PRIVATE_MANIFEST_PATH])
    create('mta_client_receive_factory', old_rows['mta_client_receive_factory'], [root('ASSET_ROOT'),
        root('ASSET_PHYSICAL_ROOT', True), assignment('SOURCE_MANIFEST_SHA', old_private[2], private_pin[2]),
        assignment('F_SHA', old_rows['mta_client_executor'][2], executor[2])], True)
    create('mta_client_receive_boot', old_rows['mta_client_receive_boot'], [root('ROOT'), root('PHYSICAL_ROOT', True),
        assignment('CLIENT_MANIFEST_SHA', old_private[2], private_pin[2]),
        assignment('F37_SHA', old_rows['mta_client_executor'][2], executor[2]),
        source_tuple('mta_client_receive_factory', old_rows['mta_client_receive_factory'], new_pins['mta_client_receive_factory']),
        source_tuple('mta_client_state_bridge', old_rows['mta_client_state_bridge'], new_pins['mta_client_state_bridge'])], True)
    create('mta_client_service_owner', old_rows['mta_client_service_owner'], [root('ROOT'),
        assignment('BOOT_PIN', old_rows['mta_client_receive_boot'][1:], new_pins['mta_client_receive_boot'][1:]),
        dict(name='held_physical_root', before="        physical = '/var/volatile/tmp/" + ROOT_BEFORE + "'\n",
             after="        physical = '/var/volatile/tmp/" + ROOT_AFTER + "'\n", count=1),
        source_tuple('mta_filecenter_companion', original_companion[1:], MUTEX_SOURCE)])
    owner = new_pins['mta_client_service_owner']
    need(helpers.owner_context(outputs[owner[0]]) == helpers.owner_context(inputs[old_rows['mta_client_service_owner'][0]]) and
         literal_assignment(outputs[owner[0]], 'FILECENTER_PINS') ==
         tuple((name, size, sha) for name, path, size, sha in fc_rows), 'owner_original_context_actual_mutex_fc9')
    ordinary_new, changes = copy.deepcopy(ordinary), []
    for index, row in enumerate(ordinary_new['sources']):
        if row['module'] in CHANGED:
            path, size, sha = new_pins[row['module']]
            after = dict(module=row['module'], path=path, bytes=size, sha256=sha)
            changes.append([index, copy.deepcopy(row), after])
            ordinary_new['sources'][index] = after
    outputs[MANIFEST_PATH] = jraw(ordinary_new)
    manifest_pin = pin(MANIFEST_PATH, outputs[MANIFEST_PATH])
    rows = tuple((row['module'], row['path'], row['bytes'], row['sha256']) for row in ordinary_new['sources'])
    private_rows = tuple(('runtime35/' + row['module'], row['path'], row['bytes'], row['sha256'])
                         for row in private_new['sources'])
    runner_edits = [root('STATE_ROOT', True), root('STATE_ALIAS')]
    runner_edits.extend(source_tuple(name, old_rows[name], new_pins[name], 2 if name == 'mta_client_executor' else 1)
                        for name in CHANGED)
    create('mta_formal_receive_session', old_runner, runner_edits, True)
    core = new_pins['mta_formal_receive_session']
    payload = rows + current['HELPERS'] + private_rows + (current['WPA'], current['MONITOR'])
    changed = tuple(row[0] for row, old in zip(payload, original_payload) if row != old)
    need(len(payload) == len({row[0] for row in payload}) == 75 and changed == CHANGED_PAYLOAD_ROLES and
         sum(row[2] for row in payload) == PAYLOAD_BYTES <= PAYLOAD_CAP and len(mechanical) == 6,
         'six_mechanical75_same_size')
    combined = dict(inputs, **outputs)
    for row, old in zip(payload, original_payload):
        need(row[0] == old[0] and (len(combined[row[1]]), digest(combined[row[1]])) == row[2:], 'new75_actual_pin')
        if row[0] not in CHANGED_PAYLOAD_ROLES:
            need(row == old and combined[row[1]] == inputs[old[1]], 'unchanged69_payload_bytes')
    for row, old in zip(fc_rows, original_fc):
        need((len(inputs[row[1]]), digest(inputs[row[1]])) == row[2:], 'new_fc9_actual_pin')
        if row[0] != 'mta_filecenter_companion':
            need(row == old and inputs[row[1]] == inputs[old[1]], 'unchanged_fc8_bytes')
    helpers.ROOT_AFTER = ROOT_AFTER
    helpers.validate_runner(outputs[core[0]], rows, private_rows, current['HELPERS'], current['WPA'], current['MONITOR'])
    factory_raw = outputs[new_pins['mta_client_receive_factory'][0]]
    boot_raw = outputs[new_pins['mta_client_receive_boot'][0]]
    need(literal_assignment(factory_raw, 'STARTUP_READ_SECONDS') == 20.0 and
         helpers.profile_method(factory_raw) == helpers.profile_method(inputs[old_rows['mta_client_receive_factory'][0]]) and
         literal_assignment(boot_raw, 'F37_SHA') == executor[2] and
         ("    ('mta_client_executor', " + str(executor[1]) + ', F37_SHA),\n').encode('ascii') in boot_raw and
         ("SOURCE_PINS[0] != ('mta_client_executor', " + str(executor[1]) + ', F37_SHA)').encode('ascii') in boot_raw and
         literal_assignment(factory_raw, 'F_SHA') == executor[2] and
         factory_raw.count(("    ('mta_client_executor', " + str(executor[1]) + ', F_SHA),\n').encode('ascii')) == 1,
         'retained_prepare20_cache_executor_binding')
    manifests = [dict(source=list(old_manifest), candidate=list(manifest_pin), private=False, changes=changes),
        dict(source=list(old_private), candidate=list(private_pin), private=True,
             changes=[[private_index, private['sources'][private_index], private_new['sources'][private_index]]])]
    helpers.validate_manifest_inverse(combined, manifests)
    spec = dict(schema='p011-receive-fc-mutex-v1-graph-delta', root=ROOT_AFTER, mother=list(MOTHER),
        mechanical=mechanical, mutex_business=mutex, manifests=manifests,
        mechanical_closure_count=6, retained_prepare20_business_closure_count=1, mutex_business_closure_count=1,
        changed_payload_roles=list(changed), unchanged_payload_roles=69, private_roles_exact=34,
        payload_bytes=PAYLOAD_BYTES, payload_cap=PAYLOAD_CAP, payload_growth=0,
        filecenter_bytes=FILECENTER_BYTES, filecenter_cap=FILECENTER_CAP, filecenter_growth=1568,
        filecenter_changed_roles=['mta_filecenter_companion'], filecenter_exact_roles=8,
        inherited_owner_scope_fc_http_cache_prepare20_provenance_preserved=True,
        startup_prepare_seconds=20.0, startup_collector_seconds=10.0, owner_context_preserved=True,
        native_authority_changed=False, outer_deadlines_preserved=True, close_method_bytes_preserved=True,
        state_protocol_proc_native_wpa_monitor_unchanged=True, cache_data_not_authority=True,
        blocking_file_io_preemption_verified=False, device_tested=False, rf_requested=False,
        phone_tested=False, send_graph_changed=False)
    outputs[SPEC_PATH] = jraw(spec)
    need(len(outputs[SPEC_PATH]) <= 131072, 'finite_graph_delta_metadata')
    delta_pin = pin(SPEC_PATH, outputs[SPEC_PATH])
    origin = {path: pin(path, raw) for path, raw in inputs.items()}
    need(not set(origin).intersection(outputs), 'immutable_output_partition')
    origin.update((path, pin(path, raw)) for path, raw in outputs.items())
    report = dict(schema='p011-receive-fc-mutex-v1-graph-generation', status='SOURCE_DERIVED_NOT_DEVICE_TESTED',
        generator=list(pin(SELF, inputs[SELF])), mother=list(MOTHER), generator_mother=list(GENERATOR_MOTHER),
        source_origin_count=len(origin) + 1, mechanical_closure_count=6,
        retained_prepare20_business_closure_count=1, new_mutex_business_closure_count=1,
        mutex_source=list(MUTEX_SOURCE), mutex_growth=1568, mutex_changed_methods=mutex['delta_expected']['changed_methods'],
        mutex_added_methods=mutex['delta_expected']['added_methods'],
        changed_payload_roles=list(changed), exact_payload_roles=69, private_roles_exact=34,
        payload_bytes=PAYLOAD_BYTES, payload_cap=PAYLOAD_CAP, payload_remaining=PAYLOAD_CAP - PAYLOAD_BYTES,
        filecenter_bytes=FILECENTER_BYTES, filecenter_cap=FILECENTER_CAP,
        filecenter_remaining=FILECENTER_CAP - FILECENTER_BYTES, filecenter_sources=9, filecenter_exact_roles=8,
        filecenter_changed_roles=['mta_filecenter_companion'], root=ROOT_AFTER,
        inherited_owner_scope_fc_http_cache_prepare20_provenance_preserved=True,
        startup_prepare_seconds=20.0, startup_collector_seconds=10.0, owner_context_preserved=True,
        state_protocol_proc_native_wpa_monitor_unchanged=True, outer_deadlines_preserved=True,
        native_authority_changed=False, cache_data_not_authority=True,
        output_pins=[list(pin(path, raw)) for path, raw in sorted(outputs.items())], definitions_path=DEFINITIONS,
        definitions_and_report_pins_omitted_to_avoid_cycles=True, old_main_prepare_verify_called=False,
        old_tests_replayed=0, device_tested=False, stage_tested=False, phone_tested=False, rf_requested=False,
        new_device_root_checked=False, send_graph_changed=False, whole_close_verified=False,
        blocking_file_io_preemption_verified=False, profile_cache_performance_verified=False)
    outputs[REPORT_PATH] = jraw(report)
    report_pin = pin(REPORT_PATH, outputs[REPORT_PATH])
    origin[REPORT_PATH] = report_pin
    source_pins = tuple(origin[path] for path in sorted(origin))
    constants = dict(MOTHER=MOTHER, GENERATOR_MOTHER=GENERATOR_MOTHER,
        MANIFEST=manifest_pin, PRIVATE_MANIFEST=private_pin, RUNNER=core, EXECUTOR_PIN=executor,
        OLD_MANIFEST=old_manifest, ORIGINAL_MANIFEST=old_manifest, OLD_PRIVATE_MANIFEST=old_private,
        DELTA_SPEC=delta_pin, GENERATION=report_pin, ROOT_BEFORE=ROOT_BEFORE, ROOT_AFTER=ROOT_AFTER,
        STATE_ROOT='/var/volatile/tmp/' + ROOT_AFTER, STATE_ALIAS='/tmp/' + ROOT_AFTER, RUNTIME_PREFIX=RUNTIME,
        CHANGED=CHANGED, CHANGED_PAYLOAD_ROLES=CHANGED_PAYLOAD_ROLES, MECHANICAL_CLOSURE_COUNT=6,
        BUSINESS_CLOSURE_COUNT=1, BUSINESS_EXPECTED=current['BUSINESS_EXPECTED'],
        PAYLOAD_BYTES=PAYLOAD_BYTES, PAYLOAD_CAP=PAYLOAD_CAP, MOTHER_PAYLOAD_BYTES=PAYLOAD_BYTES,
        FILECENTER_BYTES=FILECENTER_BYTES, FILECENTER_CAP=FILECENTER_CAP,
        ORIGIN_SOURCE_PINS=source_pins, ORIGINAL_PAYLOAD_ROWS=original_payload, ORIGINAL_FILECENTER_ROWS=original_fc,
        ORDINARY_ROWS=rows, PRIVATE_ROWS=private_rows, FILECENTER_SOURCES=fc_rows,
        MECHANICAL_EXPECTED=mechanical, MANIFEST_EXPECTED=manifests, DELTA_EXPECTED=spec, GENERATION_EXPECTED=report,
        ORIGINAL_MANIFEST_RAW=inputs[old_manifest[0]], OLD_PRIVATE_RAW=inputs[old_private[0]],
        CURRENT_EXPECTED=current, MUTEX_EXPECTED=mutex, MUTEX_BUSINESS_CLOSURE_COUNT=1)
    definitions, definitions_proof = derive_definitions(mother, constants, own)
    outputs[DEFINITIONS] = definitions
    need(len(outputs) == 11 and len(source_pins) == report['source_origin_count'] and
         all(path.startswith(PREFIX) or path in (DEFINITIONS, MANIFEST_PATH, PRIVATE_MANIFEST_PATH) for path in outputs),
         'actual_eleven_output_partition')
    facts = dict(report, definitions_derivation=definitions_proof,
                 complete_output_pins=[list(pin(path, raw)) for path, raw in sorted(outputs.items())])
    for path, raw in inputs.items():
        need(read_pin(pin(path, raw)) == raw, 'input_preserved_after_prepare')
    return outputs, facts, inputs


def write_outputs(outputs, inputs):
    """Explicit fixed namespace publication; preflight all, EXCL or byte-identical."""
    need(type(outputs) is dict and len(outputs) == 11, 'eleven_outputs_required')
    destinations = {}
    for path, raw in outputs.items():
        need(type(raw) is bytes and 0 < len(raw) <= 2097152 and
             (path.startswith(PREFIX) or path in (DEFINITIONS, MANIFEST_PATH, PRIVATE_MANIFEST_PATH)) and
             path != SELF and path not in inputs, 'output_namespace')
        target = scoped(path, True)
        if target.exists():
            need(stat.S_ISREG(target.lstat().st_mode) and target.lstat().st_nlink == 1 and
                 read_pin(pin(path, raw)) == raw, 'existing_output_incompatible:' + path)
        destinations[path] = target
    for path, raw in inputs.items():
        need(read_pin(pin(path, raw)) == raw, 'input_preserved_before_write')
    created, retained = [], []
    for path, raw in outputs.items():
        target = destinations[path]
        if target.exists():
            need(read_pin(pin(path, raw)) == raw, 'retained_output_changed:' + path)
            retained.append(path)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target = scoped(path, True)
            with target.open('xb') as stream:
                need(stream.write(raw) == len(raw), 'exclusive_short_write')
                stream.flush()
                os.fsync(stream.fileno())
            created.append(path)
        need(read_pin(pin(path, raw)) == raw, 'actual_output_readback:' + path)
    for path, raw in inputs.items():
        need(read_pin(pin(path, raw)) == raw, 'input_preserved_after_write')
    return created, retained


def main():
    args = sys.argv[1:]
    need(args in ([], ['--write']), 'source_or_explicit_write_only')
    outputs, facts, inputs = prepare()
    value = dict(mode='SOURCE_DERIVATION_NO_WRITES', planned_outputs=facts['complete_output_pins'],
                 payload_bytes=facts['payload_bytes'], payload_remaining=facts['payload_remaining'],
                 filecenter_bytes=facts['filecenter_bytes'], filecenter_remaining=facts['filecenter_remaining'],
                 source_origin_count=facts['source_origin_count'], device_tested=False)
    if args:
        created, retained = write_outputs(outputs, inputs)
        value.update(mode='EXCL_OR_EXACT_EXISTING_OUTPUTS', created=created, retained_identical=retained)
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
