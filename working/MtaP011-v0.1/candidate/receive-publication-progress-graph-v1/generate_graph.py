"""PC-only headless publication-progress75 derivation; no old graph/test entry.

Fixed current provenance is read once into a flat byte snapshot. Pure packing
interfaces are selected as AST/literals, never imported through old verifier
chains. Six runtime files, two manifests, delta/report and definitions are new.
No Navigation/UIWorker/GUI/sender output or device/RF operation is available.
Default SOURCE only plans; --write uses exclusive fresh destinations.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys


BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-publication-progress-graph-v1/'
RUNTIME = PREFIX + 'runtime/'
SELF = PREFIX + 'generate_graph.py'
DEFINITIONS = 'host/formal_receive_publication_progress_v1_definitions.py'
MANIFEST_PATH = 'host/formal_receive_publication_progress_v1_definition_manifest.json'
PRIVATE_MANIFEST_PATH = 'host/formal_receive_publication_progress_v1_private_source_manifest.json'
SPEC_PATH = PREFIX + 'graph-exactsource-delta.json'
REPORT_PATH = PREFIX + 'graph-generation.json'
MOTHER = ('host/formal_receive_proc_freezer_v1_definitions.py', 114824,
          '3eb522f95f199a1efea2c2d1505a76ab6677f7f1f419e54d64d5a0866cafc21a')
FACTORY = ('candidate/receive-publication-progress-v1/runtime/mta_client_receive_factory.py', 99255,
           'b7f771bb58e9238474ebe6cb2b64604dc0f4bcd79eb7743e48b8f9a028263664')
DIAG_GENERATOR = ('candidate/receive-publication-progress-v1/generate.py', 16140,
                  'd4c8a7aea6e0452469847f53fdecbca756c347d524a9351d3b9a4eebb3bca988')
DIAG_DELTA = ('candidate/receive-publication-progress-v1/publication-exactsource-delta.json', 9609,
              'c335cc3e5591a33c60103a81e301bc92f51b5c52592fecf578ed8d6cdcd6b228')
DIAG_REPORT = ('candidate/receive-publication-progress-v1/publication-generation.json', 2611,
               '46da96f9b5d14a13abfbc598a80c15ea97319ec72fdc86261590d0efb51f9619')
DIAG_PHONE = ('candidate/receive-publication-progress-v1/runtime/phone_discovery_session.py', 28352,
              'cdfcec298c2da5b2ec2eff931b06da4381c56ddcba39a163cb8b58dad4108d12')
ROOT_BEFORE = 'p011-mta-rx-freezer-v1'
ROOT_AFTER = 'p011-mta-rx-progress-v1'
CHANGED = ('mta_client_executor', 'mta_client_receive_factory', 'mta_client_state_bridge',
           'mta_client_receive_boot', 'mta_client_service_owner')
PRIVATE_CHANGED = ('mta_client_executor',)
CHANGED_PAYLOAD_ROLES = CHANGED + ('runtime35/mta_client_executor',)
MECHANICAL_CLOSURE_COUNT = 6
BUSINESS_CLOSURE_COUNT = 1
INTERFACE_CONSTANTS = ('CHECKER', 'TRANSPORT', 'HELPERS', 'WPA', 'MONITOR', 'MODULE_NAMES',
    'PRIVATE_MODULE_NAMES', 'TRIAL_BOOL_FIELDS', 'TRIAL_REASONS', 'TARGET_COMMON', 'TARGET_SERVICE',
    'FILECENTER_SOURCES')
INTERFACE_FUNCTIONS = ('load_checker', '_short_chunks', 'parse_trial_facts')
INTERFACE_LEAF = ('host/device_receive_interactive_v1_check.py', 51764,
                  '85744bf1c282b55b997911222f9dfb83b5f3ffdb9badc956017ef551521c58ca')
INTERFACE_BRIDGES = (
    ('host/formal_receive_alias_clock_v1_definitions.py', 19468,
     '7bd0155ae2ddcb0892bf53e0429bd323b02046b8c5a365531fb929bce7e9e6e1'),
    ('host/formal_receive_compat_v2_definitions.py', 9834,
     '9836f38f5fe48b7ef2e0f5a33f8b58a2ad80648c572410d54e7892f7d05e0b04'),
    ('host/formal_receive_compat_v1_definitions.py', 8029,
     '0a348aef9b10033bd0cde8a87b1cc2860f7c23d0a1afd9207ebb12667c101e12'),
)


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, raw):
    return path, len(raw), digest(raw)


def jraw(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def scoped(path):
    target = BASE / path
    need(not target.is_symlink() and target.resolve().is_relative_to(BASE.resolve()), 'graph_path_scope')
    return target


def read_pin(row):
    raw = scoped(row[0]).read_bytes()
    need((len(raw), digest(raw)) == row[1:], 'graph_actual_pin:' + row[0])
    return raw


def literal_assignment(raw, name):
    rows = [node for node in ast.parse(raw.decode('ascii')).body if isinstance(node, ast.Assign) and
            len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(rows) == 1, 'single_literal:' + name)
    return ast.literal_eval(rows[0].value)


def source_function(raw, name):
    text = raw.decode('ascii')
    rows = [node for node in ast.parse(text).body if isinstance(node, ast.FunctionDef) and node.name == name]
    need(len(rows) == 1, 'single_pure_function:' + name)
    return ast.get_source_segment(text, rows[0])


def interface(raw, name, inputs, seen=()):
    """Static fixed _old.NAME forwarding only; no module body or old verifier execution."""
    need(len(seen) < 16 and (digest(raw), name) not in seen, 'finite_interface_alias')
    tree, found = ast.parse(raw.decode('ascii')), []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return 'function', ast.get_source_segment(raw.decode('ascii'), node)
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id == name:
                found.append(node.value)
            if isinstance(target, ast.Tuple) and isinstance(node.value, ast.Tuple):
                for left, right in zip(target.elts, node.value.elts):
                    if isinstance(left, ast.Name) and left.id == name:
                        found.append(right)
    need(len(found) == 1, 'fixed_interface_assignment:' + name)
    value, seen = found[0], seen + ((digest(raw), name),)
    if isinstance(value, ast.Name):
        return interface(raw, value.id, inputs, seen)
    if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name) and value.value.id == '_old':
        mother = literal_assignment(raw, 'ORIGINAL')
        need(mother[0] in inputs and (len(inputs[mother[0]]), digest(inputs[mother[0]])) == mother[1:],
             'actual_interface_ancestor_pin')
        return interface(inputs[mother[0]], value.attr, inputs, seen)
    return 'literal', ast.literal_eval(value)


def replay(raw, edits, inverse=False):
    for row in reversed(edits) if inverse else edits:
        before, after = row['after' if inverse else 'before'].encode('ascii'), row['before' if inverse else 'after'].encode('ascii')
        need(raw.count(before) == row['count'], 'exact_edit_count:' + row['name'])
        raw = raw.replace(before, after)
    return raw


def definition_rows(raw):
    text = raw.decode('ascii')
    return tuple((type(node).__name__, node.name, node.lineno, node.end_lineno, ast.get_source_segment(text, node))
        for node in ast.walk(ast.parse(text, feature_version=(3, 5))) if isinstance(node, (ast.FunctionDef, ast.ClassDef)))


def validate_delta(before, after, edits, functions_unchanged=False):
    inverse = replay(after, edits, True)
    need(replay(before, edits) == after and inverse == before, 'complete_source_byte_inverse')
    need(ast.dump(ast.parse(inverse.decode('ascii')), include_attributes=True) ==
         ast.dump(ast.parse(before.decode('ascii')), include_attributes=True), 'complete_position_ast_inverse')
    old, new = definition_rows(before), definition_rows(after)
    need(tuple(row[:4] for row in old) == tuple(row[:4] for row in new) and
         len(before.splitlines()) == len(after.splitlines()), 'mechanical_definition_lines')
    if functions_unchanged:
        need(old == new, 'mechanical_all_definitions_byte_exact')


def assignment(name, before, after):
    return dict(name=name + '_constant', before=name + ' = ' + repr(before) + '\n',
                after=name + ' = ' + repr(after) + '\n', count=1)


def source_tuple(name, before, after, count=1):
    return dict(name=name + '_tuple', before='    ' + repr((name,) + before[1:]) + ',\n',
                after='    ' + repr((name,) + after[1:]) + ',\n', count=count)


def validate_runner(raw, rows, private_rows, helpers, wpa, monitor):
    need(literal_assignment(raw, 'STATE_ROOT') == '/var/volatile/tmp/' + ROOT_AFTER and
         literal_assignment(raw, 'STATE_ALIAS') == '/tmp/' + ROOT_AFTER, 'runner_roots')
    need(literal_assignment(raw, 'ROLE_PINS') == tuple((n, size, sha) for n, p, size, sha in rows) and
         literal_assignment(raw, 'PRIVATE_PINS') == tuple((n[10:], size, sha) for n, p, size, sha in private_rows) and
         literal_assignment(raw, 'HELPER_PINS') == tuple((n, size, sha) for n, p, size, sha in helpers) and
         literal_assignment(raw, 'WPA_PIN') == (wpa[0], wpa[2], wpa[3]) and
         literal_assignment(raw, 'MONITOR_PIN') == (monitor[0], monitor[2], monitor[3]), 'runner_exact75_pins')


DEFINITION_TAIL = '''
def manifest_rows(raw, private=False):
    value = json.loads(raw.decode('ascii'))
    original = json.loads((OLD_PRIVATE_RAW if private else ORIGINAL_MANIFEST_RAW).decode('ascii'))
    expected = PRIVATE_ROWS if private else ORDINARY_ROWS
    keys = {'schema', 'sources', 'previous_manifest_sha256'} if private else {'schema', 'sources'}
    need(type(value) is dict and set(value) == keys and value['schema'] == original['schema'] and
         type(value['sources']) is list and len(value['sources']) == 35 and
         (not private or value['previous_manifest_sha256'] == OLD_PRIVATE_MANIFEST[2]), 'progress_manifest_shape')
    rows = tuple(('runtime35/' + row['module'] if private else row['module'], row['path'], row['bytes'], row['sha256'])
                 for row in value['sources'])
    need(rows == expected, 'progress_manifest_exact_rows')
    return rows


def verify_inputs(inputs):
    for path, size, sha in ORIGIN_SOURCE_PINS:
        need(path in inputs and (len(inputs[path]), digest(inputs[path])) == (size, sha), 'progress_flat_pin')
    need(inputs[OLD_MANIFEST[0]] == ORIGINAL_MANIFEST_RAW and
         inputs[OLD_PRIVATE_MANIFEST[0]] == OLD_PRIVATE_RAW, 'progress_original_manifests')
    spec = json.loads(inputs[DELTA_SPEC[0]].decode('ascii'))
    need(spec == DELTA_EXPECTED, 'progress_exact_delta_metadata')
    for entry in MECHANICAL_EXPECTED:
        before, after = inputs[entry['source'][0]], inputs[entry['candidate'][0]]
        validate_delta(before, after, entry['edits'], entry['functions_unchanged'])
    for entry in MANIFEST_EXPECTED:
        old = json.loads(inputs[entry['source'][0]].decode('ascii'))
        current = json.loads(inputs[entry['candidate'][0]].decode('ascii'))
        restored = copy.deepcopy(current)
        for index, before, after in entry['changes']:
            need(old['sources'][index] == before and current['sources'][index] == after, 'progress_manifest_delta')
            restored['sources'][index] = before
        if entry['private']:
            restored['previous_manifest_sha256'] = old['previous_manifest_sha256']
        need(restored == old and jraw(current) == inputs[entry['candidate'][0]], 'progress_manifest_inverse')
    payload = manifest_rows(inputs[MANIFEST[0]]) + HELPERS + manifest_rows(inputs[PRIVATE_MANIFEST[0]], True) + (WPA, MONITOR)
    need(len(payload) == 75 and len(set(row[0] for row in payload)) == 75, 'progress75_unique')
    changed = []
    for row, before in zip(payload, ORIGINAL_PAYLOAD_ROWS):
        need(row[0] == before[0] and (len(inputs[row[1]]), digest(inputs[row[1]])) == row[2:], 'progress75_actual')
        if row[0] in CHANGED_PAYLOAD_ROLES:
            need(row != before, 'progress_changed_role')
            changed.append(row[0])
        else:
            need(row == before and inputs[row[1]] == inputs[before[1]], 'progress69_original_roles')
    need(tuple(changed) == CHANGED_PAYLOAD_ROLES and sum(row[2] for row in payload) == PAYLOAD_BYTES <= 4194304,
         'progress6_changed_budget')
    validate_runner(inputs[RUNNER[0]], ORDINARY_ROWS, PRIVATE_ROWS, HELPERS, WPA, MONITOR)
    need(len(FILECENTER_SOURCE_PINS) == 9 and sum(row[2] for row in FILECENTER_SOURCE_PINS) == 113690,
         'progress_fc9_budget')
    for name, path, size, sha in FILECENTER_SOURCE_PINS:
        need((len(inputs[path]), digest(inputs[path])) == (size, sha), 'progress_fc9_original')
    need(json.loads(inputs[GENERATION[0]].decode('ascii')) == GENERATION_EXPECTED, 'progress_generation_exact')
    return MECHANICAL_CLOSURE_COUNT
'''


def load_inputs():
    inputs = {MOTHER[0]: read_pin(MOTHER)}
    mother = inputs[MOTHER[0]]
    for row in literal_assignment(mother, 'ORIGIN_SOURCE_PINS'):
        inputs[row[0]] = read_pin(row)
    for row in (FACTORY, DIAG_GENERATOR, DIAG_DELTA, DIAG_REPORT, DIAG_PHONE):
        inputs[row[0]] = read_pin(row)
    for row in INTERFACE_BRIDGES + (INTERFACE_LEAF,):
        inputs[row[0]] = read_pin(row)
    diag = json.loads(inputs[DIAG_REPORT[0]].decode('ascii'))
    for row in diag['source_pins']:
        inputs[row[0]] = read_pin(tuple(row))
    inputs[SELF] = scoped(SELF).read_bytes()
    return inputs


def assemble(inputs):
    """Derive actual bytes from a flat snapshot; no old main/build/verify/suite call."""
    mother = inputs[MOTHER[0]]
    need((len(mother), digest(mother)) == MOTHER[1:] and
         len(literal_assignment(mother, 'ORIGIN_SOURCE_PINS')) == 208, 'fixed_current_freezer208')
    for path, size, sha in literal_assignment(mother, 'ORIGIN_SOURCE_PINS') + (FACTORY, DIAG_GENERATOR, DIAG_DELTA, DIAG_REPORT, DIAG_PHONE):
        need((len(inputs[path]), digest(inputs[path])) == (size, sha), 'actual_flat_source_pin')
    need((len(inputs[INTERFACE_LEAF[0]]), digest(inputs[INTERFACE_LEAF[0]])) == INTERFACE_LEAF[1:],
         'actual_pure_interface_leaf')
    values = {}
    for name in INTERFACE_CONSTANTS:
        kind, value = interface(mother, name, inputs)
        need(kind == 'literal', 'pure_interface_literal')
        values[name] = value
    pure = []
    for name in INTERFACE_FUNCTIONS:
        kind, value = interface(mother, name, inputs)
        need(kind == 'function', 'pure_interface_function')
        pure.append(value)
    old_manifest, old_private, old_runner = (literal_assignment(mother, name) for name in ('MANIFEST', 'PRIVATE_MANIFEST', 'RUNNER'))
    ordinary, private = (json.loads(inputs[row[0]].decode('ascii')) for row in (old_manifest, old_private))
    old_rows = dict((row['module'], (row['path'], row['bytes'], row['sha256'])) for row in ordinary['sources'])
    old_private_rows = tuple(('runtime35/' + r['module'], r['path'], r['bytes'], r['sha256']) for r in private['sources'])
    original_payload = tuple((r['module'], r['path'], r['bytes'], r['sha256']) for r in ordinary['sources']) + values['HELPERS'] + old_private_rows + (values['WPA'], values['MONITOR'])
    need(len(original_payload) == 75 and sum(r[2] for r in original_payload) == 4191766 and
         FACTORY[1] - old_rows['mta_client_receive_factory'][1] == 1498, 'current75_diag_growth')
    outputs, mechanical, new_pins = {}, [], {}
    def create(name, source, edits, functions_unchanged=False):
        before = inputs[source[0]]
        result = replay(before, edits)
        validate_delta(before, result, edits, functions_unchanged)
        path = RUNTIME + name + '.py'
        outputs[path], new_pins[name] = result, pin(path, result)
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
    private_index = next(i for i, r in enumerate(private_new['sources']) if r['module'] == 'mta_client_executor')
    private_new['sources'][private_index] = dict(module='mta_client_executor', path=executor[0], bytes=executor[1], sha256=executor[2])
    private_new['previous_manifest_sha256'] = old_private[2]
    outputs[PRIVATE_MANIFEST_PATH] = jraw(private_new)
    private_pin = pin(PRIVATE_MANIFEST_PATH, outputs[PRIVATE_MANIFEST_PATH])
    create('mta_client_receive_factory', FACTORY, [root('ASSET_ROOT'), root('ASSET_PHYSICAL_ROOT', True),
        assignment('SOURCE_MANIFEST_SHA', old_private[2], private_pin[2]),
        assignment('F_SHA', old_rows['mta_client_executor'][2], executor[2]),
        dict(name='factory_executor_size', before="    ('mta_client_executor', " + str(old_rows['mta_client_executor'][1]) + ", F_SHA),\n",
             after="    ('mta_client_executor', " + str(executor[1]) + ", F_SHA),\n", count=1)], True)
    boot_edits = [root('ROOT'), root('PHYSICAL_ROOT', True),
        assignment('CLIENT_MANIFEST_SHA', old_private[2], private_pin[2]),
        assignment('F37_SHA', old_rows['mta_client_executor'][2], executor[2]),
        source_tuple('mta_client_receive_factory', old_rows['mta_client_receive_factory'], new_pins['mta_client_receive_factory']),
        source_tuple('mta_client_state_bridge', old_rows['mta_client_state_bridge'], new_pins['mta_client_state_bridge']),
        dict(name='boot_executor_size_table_and_source_shape',
             before="('mta_client_executor', " + str(old_rows['mta_client_executor'][1]) + ', F37_SHA)',
             after="('mta_client_executor', " + str(executor[1]) + ', F37_SHA)', count=2)]
    create('mta_client_receive_boot', old_rows['mta_client_receive_boot'], boot_edits)
    create('mta_client_service_owner', old_rows['mta_client_service_owner'], [root('ROOT'),
        assignment('BOOT_PIN', old_rows['mta_client_receive_boot'][1:], new_pins['mta_client_receive_boot'][1:]),
        dict(name='held_physical_root', before="        physical = '/var/volatile/tmp/" + ROOT_BEFORE + "'\n",
             after="        physical = '/var/volatile/tmp/" + ROOT_AFTER + "'\n", count=1)])
    ordinary_new = copy.deepcopy(ordinary)
    changes = []
    for index, row in enumerate(ordinary_new['sources']):
        if row['module'] in CHANGED:
            path, size, sha = new_pins[row['module']]
            after = dict(module=row['module'], path=path, bytes=size, sha256=sha)
            changes.append([index, copy.deepcopy(row), after])
            ordinary_new['sources'][index] = after
    outputs[MANIFEST_PATH] = jraw(ordinary_new)
    manifest_pin = pin(MANIFEST_PATH, outputs[MANIFEST_PATH])
    rows = tuple((r['module'], r['path'], r['bytes'], r['sha256']) for r in ordinary_new['sources'])
    private_rows = tuple(('runtime35/' + r['module'], r['path'], r['bytes'], r['sha256']) for r in private_new['sources'])
    runner_edits = [root('STATE_ROOT', True), root('STATE_ALIAS')]
    runner_edits.extend(source_tuple(name, old_rows[name], new_pins[name], 2 if name == 'mta_client_executor' else 1) for name in CHANGED)
    create('mta_formal_receive_session', old_runner, runner_edits, True)
    core = new_pins['mta_formal_receive_session']
    payload = rows + values['HELPERS'] + private_rows + (values['WPA'], values['MONITOR'])
    changed = tuple(row[0] for row, before in zip(payload, original_payload) if row != before)
    total = sum(row[2] for row in payload)
    need(len(payload) == 75 and len(set(row[0] for row in payload)) == 75 and changed == CHANGED_PAYLOAD_ROLES and
         4191766 < total <= 4194304 and len(mechanical) == 6, 'actual6_changed_69_exact_budget')
    for row, before in zip(payload, original_payload):
        if row[0] not in CHANGED_PAYLOAD_ROLES:
            need(row == before and inputs[row[1]] == inputs[before[1]], 'unchanged69_original_bytes')
    validate_runner(outputs[core[0]], rows, private_rows, values['HELPERS'], values['WPA'], values['MONITOR'])
    need(literal_assignment(outputs[executor[0]], 'MODULES') == values['PRIVATE_MODULE_NAMES'], 'executor35_order')
    manifests = [dict(source=list(old_manifest), candidate=list(manifest_pin), private=False, changes=changes),
        dict(source=list(old_private), candidate=list(private_pin), private=True,
             changes=[[private_index, private['sources'][private_index], private_new['sources'][private_index]]])]
    spec = dict(schema='p011-receive-publication-progress-v1-graph-delta', root=ROOT_AFTER,
        mechanical=mechanical, manifests=manifests, factory_seed=list(FACTORY),
        factory_diagnostic_growth=1498, changed_roles=list(changed), payload_bytes=total,
        unchanged_payload_roles=69, native_proc_fc9_unchanged=True)
    outputs[SPEC_PATH] = jraw(spec)
    need(len(outputs[SPEC_PATH]) <= 131072, 'finite_graph_delta_metadata')
    delta_pin = pin(SPEC_PATH, outputs[SPEC_PATH])
    origin = dict((path, pin(path, raw)) for path, raw in inputs.items())
    need(not set(origin).intersection(outputs), 'immutable_output_partition')
    origin.update((path, pin(path, raw)) for path, raw in outputs.items())
    report = dict(schema='p011-receive-publication-progress-v1-graph-generation',
        status='MECHANICALLY_DERIVED_NOT_HOST_OR_DEVICE_TESTED', generator=list(pin(SELF, inputs[SELF])),
        source_origin_count=len(origin) + 1, mechanical_closure_count=6, business_closure_count=1,
        changed_payload_roles=list(changed), exact_payload_roles=69, payload_bytes=total,
        payload_remaining=4194304 - total, factory_diagnostic_growth=1498, root=ROOT_AFTER,
        headless_only=True, navigation_ui_outputs=False, proc_native_fc9_unchanged=True,
        output_pins=[list(pin(path, raw)) for path, raw in sorted(outputs.items())],
        definitions_path=DEFINITIONS, definitions_and_report_pins_omitted_to_avoid_cycles=True,
        old_main_build_verify_called=False, old_tests_replayed=0, device_tested=False, phone_tested=False)
    outputs[REPORT_PATH] = jraw(report)
    report_pin = pin(REPORT_PATH, outputs[REPORT_PATH])
    origin[REPORT_PATH] = report_pin
    source_pins = tuple(origin[path] for path in sorted(origin))
    constants = dict(MOTHER=MOTHER, MANIFEST=manifest_pin, PRIVATE_MANIFEST=private_pin, RUNNER=core,
        EXECUTOR_PIN=executor, OLD_MANIFEST=old_manifest, ORIGINAL_MANIFEST=old_manifest, OLD_PRIVATE_MANIFEST=old_private,
        DELTA_SPEC=delta_pin, GENERATION=report_pin, ROOT_BEFORE=ROOT_BEFORE, ROOT_AFTER=ROOT_AFTER,
        STATE_ROOT='/var/volatile/tmp/' + ROOT_AFTER, STATE_ALIAS='/tmp/' + ROOT_AFTER,
        RUNTIME_PREFIX=RUNTIME, CHANGED=CHANGED, PRIVATE_CHANGED=PRIVATE_CHANGED,
        CHANGED_PAYLOAD_ROLES=CHANGED_PAYLOAD_ROLES, MECHANICAL_CLOSURE_COUNT=6, BUSINESS_CLOSURE_COUNT=1,
        PAYLOAD_BYTES=total, ORIGIN_SOURCE_PINS=source_pins, ORIGINAL_PAYLOAD_ROWS=original_payload,
        ORDINARY_ROWS=rows, PRIVATE_ROWS=private_rows, MECHANICAL_EXPECTED=mechanical,
        MANIFEST_EXPECTED=manifests, DELTA_EXPECTED=spec, GENERATION_EXPECTED=report,
        ORIGINAL_MANIFEST_RAW=inputs[old_manifest[0]], OLD_PRIVATE_RAW=inputs[old_private[0]], **values)
    header = '\n'.join(('"""Flat headless progress75 closure; not device or phone acceptance."""',
        'import ast', 'import copy', 'import hashlib', 'import json', 'import os', 'from pathlib import Path',
        'import re', 'import stat', 'import types', '', 'BASE = Path(__file__).resolve().parents[1]') +
        tuple(name + ' = ' + repr(value) for name, value in constants.items()))
    reusable = '\n\n'.join(source_function(inputs[SELF], name) for name in
        ('need', 'digest', 'jraw', 'scoped', 'read_pin', 'literal_assignment', 'replay', 'definition_rows', 'validate_delta', 'validate_runner'))
    interfaces = '\n'.join(('SOURCE_PINS = ORIGIN_SOURCE_PINS', 'FILECENTER_SOURCE_PINS = FILECENTER_SOURCES',
        "TRIAL_FIELDS = frozenset(TRIAL_BOOL_FIELDS + ('claim_count', 'reason'))", 'json_bytes = jraw'))
    interfaces += '\n\n' + source_function(inputs[INTERFACE_LEAF[0]], '_meta')
    definitions = (header + '\n\n' + reusable + '\n\n' + interfaces + '\n\n' + '\n\n'.join(pure) +
                   DEFINITION_TAIL + '\n\n' + source_function(mother, 'make_source') + '\n').encode('ascii')
    ast.parse(definitions.decode('ascii'))
    outputs[DEFINITIONS] = definitions
    need(len(outputs) == 11 and len(source_pins) == report['source_origin_count'], 'actual11_outputs_flat_origin')
    return outputs, report, inputs


def main():
    args = sys.argv[1:]
    need(args in ([], ['--write']), 'source_plan_or_explicit_write')
    inputs = load_inputs()
    outputs, report, _ = assemble(inputs)
    if not args:
        print(json.dumps(dict(mode='SOURCE_PLAN_NO_WRITES', planned_output_bytes=dict((p, len(r)) for p, r in outputs.items()),
            payload_bytes=report['payload_bytes'], remaining=report['payload_remaining'], source_origin_count=report['source_origin_count'],
            output_written=False, future_output_pins_published=False, tests_executed=False), sort_keys=True))
        return 0
    allowed_host = {DEFINITIONS, MANIFEST_PATH, PRIVATE_MANIFEST_PATH}
    for path in outputs:
        need((path.startswith(PREFIX) or path in allowed_host) and not scoped(path).exists(), 'fresh_graph_output:' + path)
    for path, raw in inputs.items():
        need(scoped(path).read_bytes() == raw, 'original_input_before_write')
    for path, raw in outputs.items():
        target = scoped(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as handle:
            need(handle.write(raw) == len(raw), 'mechanical_short_write')
        need(target.read_bytes() == raw, 'mechanical_output_readback')
    for path, raw in inputs.items():
        need(scoped(path).read_bytes() == raw, 'all_original_inputs_preserved')
    print(json.dumps(dict(status=report['status'], outputs=[list(pin(p, r)) for p, r in sorted(outputs.items())],
        payload_bytes=report['payload_bytes'], remaining=report['payload_remaining'], source_origin_count=report['source_origin_count'],
        device_tested=False, phone_tested=False), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
