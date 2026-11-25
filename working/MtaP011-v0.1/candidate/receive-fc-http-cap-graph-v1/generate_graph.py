"""Immutable receive Scope75 graph with the two real FileCenter HTTP cap sources.

prepare() returns (outputs, facts, inputs) and only reads/derives bytes. The
default CLI reports that plan. Explicit --write preflights every output, then
creates missing files with EXCL; existing files must be exactly identical.
No old assemble/main/verify/test, subprocess, ADB, device, RF, send graph or UI
is invoked. This assembler does not certify the new physical device root.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import stat
import sys

BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-fc-http-cap-graph-v1/'
RUNTIME = PREFIX + 'runtime/'
SELF = PREFIX + 'generate_graph.py'
DEFINITIONS = 'host/formal_receive_fc_http_cap_v1_definitions.py'
MANIFEST_PATH = 'host/formal_receive_fc_http_cap_v1_definition_manifest.json'
PRIVATE_MANIFEST_PATH = 'host/formal_receive_fc_http_cap_v1_private_source_manifest.json'
SPEC_PATH = PREFIX + 'graph-exactsource-delta.json'
REPORT_PATH = PREFIX + 'graph-generation.json'
MOTHER = ('host/formal_receive_scope_dispatch_v1_definitions.py', 178958,
          'bcf738217c0821a14d732872cb1520e0e090f507272e588f8659d40b07bf28e3')
GENERATOR_MOTHER = ('candidate/receive-scope-dispatch-graph-v1/generate_graph.py', 24987,
                    'ad8932e0de8648e3e459a1c9442e29dc5f6a25dd62b91422ec93ac1ea19a955a')
FC_INPUTS = (
    ('candidate/filecenter-http-parent-cap-v1/shared/mta_toolbox_minhttp.py', 9323,
     '8ea06020e4b133665ab881e5901af9094ebc2c9d5add9d4eb37ca5b2e55a8c55'),
    ('candidate/filecenter-http-parent-cap-v1/receive/mta_filecenter_companion.py', 33630,
     '8b3ab84e17de135622b3a58e29138ca556376172e6c523eb9ab22ef44f4880ba'))
ROOT_BEFORE = 'p011-mta-rx-scope-v0001'
ROOT_AFTER = 'p011-mta-rx-fccap-v0001'
CHANGED = ('mta_client_executor', 'mta_client_receive_factory', 'mta_client_state_bridge',
           'mta_client_receive_boot', 'mta_client_service_owner')
CHANGED_PAYLOAD_ROLES = CHANGED + ('runtime35/mta_client_executor',)
FC_CHANGED = ('mta_toolbox_minhttp', 'mta_filecenter_companion')
PAYLOAD_BYTES = 4193464
FILECENTER_BYTES = 113832
FILECENTER_CAP = 131072
INTERFACE_CONSTANTS = ('CHECKER', 'TRANSPORT', 'HELPERS', 'WPA', 'MONITOR', 'MODULE_NAMES',
                       'PRIVATE_MODULE_NAMES', 'TRIAL_BOOL_FIELDS', 'TRIAL_REASONS',
                       'TARGET_COMMON', 'TARGET_SERVICE', 'FILECENTER_SOURCES')
REUSED_FUNCTIONS = ('need', 'digest', 'jraw', 'scoped', 'read_pin', 'literal_assignment',
                    'replay', 'definition_rows', 'validate_delta', 'validate_runner',
                    '_meta', 'load_checker', '_short_chunks', 'parse_trial_facts',
                    'manifest_rows', 'make_source', 'owner_context', 'validate_owner_business',
                    'scope_originals', 'validate_scope_business')


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
    need(type(path) is str and path != '' and '\\' not in path and ':' not in path and
         not path.startswith('/') and all(part not in ('', '.', '..') for part in path.split('/')),
         'relative_graph_path')
    target = BASE
    for index, part in enumerate(path.split('/')):
        target = target / part
        try:
            value = target.lstat()
        except FileNotFoundError:
            continue
        need(not stat.S_ISLNK(value.st_mode) and not getattr(value, 'st_file_attributes', 0) & 0x400,
             'graph_link_or_reparse')
        if index < len(path.split('/')) - 1:
            need(stat.S_ISDIR(value.st_mode), 'graph_ancestor_directory')
    need(target.resolve().is_relative_to(BASE.resolve()), 'graph_path_scope')
    return target


def read_pin(row):
    need(type(row) is tuple and len(row) == 3 and type(row[1]) is int and row[1] > 0 and
         type(row[2]) is str and len(row[2]) == 64, 'source_pin_shape')
    target = scoped(row[0])
    need(stat.S_ISREG(target.lstat().st_mode), 'source_regular_file')
    raw = target.read_bytes()
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


def owner_context(raw):
    text, tree = raw.decode('ascii'), ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'FixedStateServiceOwner']
    need(len(classes) == 1, 'one_owner_class')
    methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name == '_context']
    need(len(methods) == 1, 'one_owner_context')
    return ast.get_source_segment(text, methods[0])


def replay(raw, edits, inverse=False):
    for row in reversed(edits) if inverse else edits:
        before = row['after' if inverse else 'before'].encode('ascii')
        after = row['before' if inverse else 'after'].encode('ascii')
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


def validate_fc_http_delta(inputs, entries):
    """Exactly one header clamp and one receive setup override; not runtime evidence."""
    need(type(entries) is list and len(entries) == 2 and
         tuple(row['name'] for row in entries) == FC_CHANGED, 'fc_two_actual_roles')
    for row in entries:
        before, after = inputs[row['source'][0]], inputs[row['candidate'][0]]
        need((len(before), digest(before)) == tuple(row['source'][1:]) and
             (len(after), digest(after)) == tuple(row['candidate'][1:]), 'fc_actual_source_pin')
        need(len(row['edits']) == 1 and row['edits'][0]['count'] == 1 and
             replay(before, row['edits']) == after and replay(after, row['edits'], True) == before,
             'fc_whole_source_forward_inverse')
        ast.parse(before.decode('utf-8'), feature_version=(3, 5))
        ast.parse(after.decode('utf-8'), feature_version=(3, 5))
        if row['name'] == 'mta_toolbox_minhttp':
            expected = dict(name='header_original_deadline_clamp',
                before='        header_deadline = time.monotonic()+4\n',
                after='        header_deadline = min(self.deadline, time.monotonic()+4)\n', count=1)
            need(row['edits'] == [expected] and len(after) - len(before) == 20, 'fc_header_only')
        else:
            expected = dict(name='receive_original_parent_cap_setup',
                before='class _FileCenterHandler(Handler):\n',
                after=('class _FileCenterHandler(Handler):\n'
                       '    def setup(self):\n'
                       '        self.deadline = min(self.deadline, self.server.companion.until)\n'
                       '        Handler.setup(self)\n\n'), count=1)
            need(row['edits'] == [expected] and len(after) - len(before) == 122, 'fc_receive_setup_only')


def verify_inputs(inputs):
    """The new definitions' independent validator, never called by prepare()."""
    for path, size, sha in ORIGIN_SOURCE_PINS:
        need(path in inputs and (len(inputs[path]), digest(inputs[path])) == (size, sha), 'fccap_flat_pin')
    need(inputs[OLD_MANIFEST[0]] == ORIGINAL_MANIFEST_RAW and
         inputs[OLD_PRIVATE_MANIFEST[0]] == OLD_PRIVATE_RAW, 'fccap_original_manifests')
    need(json.loads(inputs[DELTA_SPEC[0]].decode('ascii')) == DELTA_EXPECTED, 'fccap_exact_delta_metadata')
    # Retain and independently audit the already measured seed provenance.
    # These are copied pure inverse validators, not historical test methods.
    validate_owner_business(inputs, OWNER_BUSINESS_EXPECTED)
    validate_scope_business(inputs, BUSINESS_EXPECTED)
    validate_fc_http_delta(inputs, FC_HTTP_EXPECTED)
    for entry in MECHANICAL_EXPECTED:
        before, after = inputs[entry['source'][0]], inputs[entry['candidate'][0]]
        validate_delta(before, after, entry['edits'], entry['functions_unchanged'])
        need(len(before) == len(after), 'fccap_equal_length_mechanical_source')
    for entry in MANIFEST_EXPECTED:
        old = json.loads(inputs[entry['source'][0]].decode('ascii'))
        current = json.loads(inputs[entry['candidate'][0]].decode('ascii'))
        restored = copy.deepcopy(current)
        for index, before, after in entry['changes']:
            need(old['sources'][index] == before and current['sources'][index] == after, 'fccap_manifest_delta')
            restored['sources'][index] = before
        if entry['private']:
            restored['previous_manifest_sha256'] = old['previous_manifest_sha256']
        need(restored == old and jraw(current) == inputs[entry['candidate'][0]], 'fccap_manifest_inverse')
    payload = manifest_rows(inputs[MANIFEST[0]]) + HELPERS + manifest_rows(inputs[PRIVATE_MANIFEST[0]], True) + (WPA, MONITOR)
    need(len(payload) == 75 and len(set(row[0] for row in payload)) == 75, 'fccap75_unique')
    changed = []
    for row, before in zip(payload, ORIGINAL_PAYLOAD_ROWS):
        need(row[0] == before[0] and (len(inputs[row[1]]), digest(inputs[row[1]])) == row[2:], 'fccap75_actual')
        if row[0] in CHANGED_PAYLOAD_ROLES:
            need(row != before, 'fccap_changed_role')
            changed.append(row[0])
        else:
            need(row == before and inputs[row[1]] == inputs[before[1]], 'fccap69_original_roles')
    need(tuple(changed) == CHANGED_PAYLOAD_ROLES and sum(row[2] for row in payload) == PAYLOAD_BYTES == 4193464 <= 4194304,
         'fccap6_changed_payload_budget')
    validate_runner(inputs[RUNNER[0]], ORDINARY_ROWS, PRIVATE_ROWS, HELPERS, WPA, MONITOR)
    need(len(FILECENTER_SOURCE_PINS) == 9 and sum(row[2] for row in FILECENTER_SOURCE_PINS) == FILECENTER_BYTES == 113832 <= 131072,
         'fccap_separate_fc9_budget')
    expected_pins = tuple((name, size, sha) for name, path, size, sha in FILECENTER_SOURCE_PINS)
    owner_row = next(row for row in ORDINARY_ROWS if row[0] == 'mta_client_service_owner')
    need(literal_assignment(inputs[owner_row[1]], 'FILECENTER_PINS') == expected_pins, 'fccap_actual_owner_fc9')
    fc_changed = []
    for row, before in zip(FILECENTER_SOURCE_PINS, ORIGINAL_FILECENTER_ROWS):
        need(row[0] == before[0] and (len(inputs[row[1]]), digest(inputs[row[1]])) == row[2:], 'fccap_fc9_actual')
        if row[0] in FC_CHANGED:
            need(row != before, 'fccap_fc_changed_role')
            fc_changed.append(row[0])
        else:
            need(row == before and inputs[row[1]] == inputs[before[1]], 'fccap_fc7_unchanged')
    need(tuple(fc_changed) == FC_CHANGED, 'fccap_only_two_fc_sources')
    need(json.loads(inputs[GENERATION[0]].decode('ascii')) == GENERATION_EXPECTED, 'fccap_generation_exact')
    return MECHANICAL_CLOSURE_COUNT


def prepare():
    """Pure read/derive; no imports of source modules or output writes."""
    need(len(ROOT_BEFORE) == len(ROOT_AFTER), 'equal_length_isolated_root')
    inputs = {MOTHER[0]: read_pin(MOTHER), GENERATOR_MOTHER[0]: read_pin(GENERATOR_MOTHER)}
    mother = inputs[MOTHER[0]]
    origin_rows = literal_assignment(mother, 'ORIGIN_SOURCE_PINS')
    need(type(origin_rows) is tuple and len(origin_rows) == 260, 'actual_scope_flat260')
    for row in origin_rows + FC_INPUTS:
        raw = read_pin(row)
        need(row[0] not in inputs or inputs[row[0]] == raw, 'flat_duplicate_identity')
        inputs[row[0]] = raw
    inputs[SELF] = scoped(SELF).read_bytes()
    values = {name: literal_assignment(mother, name) for name in INTERFACE_CONSTANTS}
    old_manifest, old_private, old_runner = (literal_assignment(mother, name) for name in ('MANIFEST', 'PRIVATE_MANIFEST', 'RUNNER'))
    ordinary, private = (json.loads(inputs[row[0]].decode('ascii')) for row in (old_manifest, old_private))
    need(jraw(ordinary) == inputs[old_manifest[0]] and jraw(private) == inputs[old_private[0]], 'mother_manifest_canonical')
    old_rows = {row['module']: (row['path'], row['bytes'], row['sha256']) for row in ordinary['sources']}
    private_rows_old = tuple(('runtime35/' + row['module'], row['path'], row['bytes'], row['sha256']) for row in private['sources'])
    original_payload = tuple((row['module'], row['path'], row['bytes'], row['sha256']) for row in ordinary['sources']) + values['HELPERS'] + private_rows_old + (values['WPA'], values['MONITOR'])
    need(len(old_rows) == 35 and len(private_rows_old) == 35 and len(original_payload) == 75 and
         sum(row[2] for row in original_payload) == PAYLOAD_BYTES and
         literal_assignment(mother, 'ROOT_AFTER') == ROOT_BEFORE and
         literal_assignment(mother, 'PAYLOAD_BYTES') == PAYLOAD_BYTES and
         original_payload == literal_assignment(mother, 'ORDINARY_ROWS') + values['HELPERS'] +
             literal_assignment(mother, 'PRIVATE_ROWS') + (values['WPA'], values['MONITOR']), 'actual_current75_scope')
    original_fc = values['FILECENTER_SOURCES']
    need(len(original_fc) == 9 and sum(row[2] for row in original_fc) == 113690, 'actual_original_fc9')
    fc_new, fc_business = [], []
    fc_pin_by_name = dict(zip(FC_CHANGED, FC_INPUTS))
    for row in original_fc:
        if row[0] not in FC_CHANGED:
            fc_new.append(row)
            continue
        after_pin = fc_pin_by_name[row[0]]
        fc_new.append((row[0],) + after_pin)
        if row[0] == 'mta_toolbox_minhttp':
            edit = dict(name='header_original_deadline_clamp', before='        header_deadline = time.monotonic()+4\n',
                        after='        header_deadline = min(self.deadline, time.monotonic()+4)\n', count=1)
        else:
            edit = dict(name='receive_original_parent_cap_setup', before='class _FileCenterHandler(Handler):\n',
                after=('class _FileCenterHandler(Handler):\n'
                       '    def setup(self):\n'
                       '        self.deadline = min(self.deadline, self.server.companion.until)\n'
                       '        Handler.setup(self)\n\n'), count=1)
        fc_business.append(dict(name=row[0], source=list(row[1:]), candidate=list(after_pin), edits=[edit]))
    validate_fc_http_delta(inputs, fc_business)
    fc_new = tuple(fc_new)
    need(sum(row[2] for row in fc_new) == FILECENTER_BYTES <= FILECENTER_CAP and
         len(fc_new) == 9 and len(fc_business) == 2, 'actual_fc9_new_budget')
    outputs, mechanical, new_pins = {}, [], {}

    def create(name, source, edits, functions_unchanged=False):
        before = inputs[source[0]]
        raw = replay(before, edits)
        validate_delta(before, raw, edits, functions_unchanged)
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
    private_new['sources'][private_index] = dict(module='mta_client_executor', path=executor[0], bytes=executor[1], sha256=executor[2])
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
    owner_edits = [root('ROOT'),
        assignment('BOOT_PIN', old_rows['mta_client_receive_boot'][1:], new_pins['mta_client_receive_boot'][1:]),
        dict(name='held_physical_root', before="        physical = '/var/volatile/tmp/" + ROOT_BEFORE + "'\n",
             after="        physical = '/var/volatile/tmp/" + ROOT_AFTER + "'\n", count=1)]
    old_fc_by_name, new_fc_by_name = ({row[0]: row[1:] for row in rows} for rows in (original_fc, fc_new))
    owner_edits.extend(source_tuple(name, old_fc_by_name[name], new_fc_by_name[name]) for name in FC_CHANGED)
    create('mta_client_service_owner', old_rows['mta_client_service_owner'], owner_edits)
    owner = new_pins['mta_client_service_owner']
    need(owner_context(outputs[owner[0]]) == owner_context(inputs[old_rows['mta_client_service_owner'][0]]),
         'measured_owner_context_byte_exact')
    need(literal_assignment(outputs[owner[0]], 'FILECENTER_PINS') ==
         tuple((name, size, sha) for name, path, size, sha in fc_new), 'actual_owner_fc9_constant')
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
    private_rows = tuple(('runtime35/' + row['module'], row['path'], row['bytes'], row['sha256']) for row in private_new['sources'])
    runner_edits = [root('STATE_ROOT', True), root('STATE_ALIAS')]
    runner_edits.extend(source_tuple(name, old_rows[name], new_pins[name], 2 if name == 'mta_client_executor' else 1) for name in CHANGED)
    create('mta_formal_receive_session', old_runner, runner_edits, True)
    core = new_pins['mta_formal_receive_session']
    payload = rows + values['HELPERS'] + private_rows + (values['WPA'], values['MONITOR'])
    changed = tuple(row[0] for row, before in zip(payload, original_payload) if row != before)
    total = sum(row[2] for row in payload)
    need(len(payload) == 75 and len(set(row[0] for row in payload)) == 75 and
         changed == CHANGED_PAYLOAD_ROLES and total == PAYLOAD_BYTES <= 4194304 and
         len(mechanical) == 6, 'actual_six_mechanical_75_budget')
    for row, before in zip(payload, original_payload):
        if row[0] not in CHANGED_PAYLOAD_ROLES:
            need(row == before and inputs[row[1]] == inputs[before[1]], 'actual69_original_payload_bytes')
    validate_runner(outputs[core[0]], rows, private_rows, values['HELPERS'], values['WPA'], values['MONITOR'])
    need(literal_assignment(outputs[executor[0]], 'MODULES') == values['PRIVATE_MODULE_NAMES'], 'executor35_order')
    boot_raw, factory_raw = outputs[new_pins['mta_client_receive_boot'][0]], outputs[new_pins['mta_client_receive_factory'][0]]
    need(literal_assignment(boot_raw, 'F37_SHA') == executor[2] and
         ("    ('mta_client_executor', " + str(executor[1]) + ', F37_SHA),\n').encode('ascii') in boot_raw and
         ("SOURCE_PINS[0] != ('mta_client_executor', " + str(executor[1]) + ', F37_SHA)').encode('ascii') in boot_raw and
         literal_assignment(factory_raw, 'F_SHA') == executor[2] and
         factory_raw.count(("    ('mta_client_executor', " + str(executor[1]) + ', F_SHA),\n').encode('ascii')) == 1,
         'actual_boot_factory_executor_binding')
    manifests = [dict(source=list(old_manifest), candidate=list(manifest_pin), private=False, changes=changes),
        dict(source=list(old_private), candidate=list(private_pin), private=True,
             changes=[[private_index, private['sources'][private_index], private_new['sources'][private_index]]])]
    spec = dict(schema='p011-receive-fc-http-cap-v1-graph-delta', root=ROOT_AFTER,
        mother=list(MOTHER), mechanical=mechanical, filecenter_http=fc_business,
        manifests=manifests, changed_roles=list(changed), payload_bytes=total,
        unchanged_payload_roles=69, private_roles_exact=34, filecenter_bytes=FILECENTER_BYTES,
        filecenter_cap=FILECENTER_CAP, filecenter_changed_roles=list(FC_CHANGED), filecenter_exact_roles=7,
        proc_native_wpa_monitor_unchanged=True, state_protocol_unchanged=True,
        measured_owner_context_preserved=True, native_business_methods_preserved=True,
        native_authority_changed=False, rf_requested=False, send_graph_changed=False)
    outputs[SPEC_PATH] = jraw(spec)
    need(len(outputs[SPEC_PATH]) <= 131072, 'finite_graph_delta_metadata')
    delta_pin = pin(SPEC_PATH, outputs[SPEC_PATH])
    origin = {path: pin(path, raw) for path, raw in inputs.items()}
    need(not set(origin).intersection(outputs), 'immutable_output_partition')
    origin.update((path, pin(path, raw)) for path, raw in outputs.items())
    report = dict(schema='p011-receive-fc-http-cap-v1-graph-generation',
        status='MECHANICALLY_DERIVED_NOT_NEW_DEVICE_TESTED', generator=list(pin(SELF, inputs[SELF])),
        mother=list(MOTHER), generator_mother=list(GENERATOR_MOTHER), source_origin_count=len(origin) + 1,
        mechanical_closure_count=6, new_http_business_source_count=2, inherited_owner_scope_business_unchanged=True,
        changed_payload_roles=list(changed), exact_payload_roles=69, private_roles_exact=34,
        payload_bytes=total, payload_remaining=4194304 - total, filecenter_bytes=FILECENTER_BYTES,
        filecenter_remaining=FILECENTER_CAP - FILECENTER_BYTES, filecenter_sources=9, filecenter_exact_roles=7,
        root=ROOT_AFTER, headless_only=True, navigation_ui_outputs=False,
        measured_owner_context_preserved=True, state_protocol_proc_native_wpa_monitor_unchanged=True,
        output_pins=[list(pin(path, raw)) for path, raw in sorted(outputs.items())], definitions_path=DEFINITIONS,
        definitions_and_report_pins_omitted_to_avoid_cycles=True, old_main_build_verify_called=False,
        old_tests_replayed=0, device_tested=False, phone_tested=False, rf_requested=False,
        new_device_root_checked=False, send_graph_changed=False, full_filecenter_parent_deadline_verified=False)
    outputs[REPORT_PATH] = jraw(report)
    report_pin = pin(REPORT_PATH, outputs[REPORT_PATH])
    origin[REPORT_PATH] = report_pin
    source_pins = tuple(origin[path] for path in sorted(origin))
    values['FILECENTER_SOURCES'] = fc_new
    constants = dict(MOTHER=MOTHER, GENERATOR_MOTHER=GENERATOR_MOTHER,
        MANIFEST=manifest_pin, PRIVATE_MANIFEST=private_pin, RUNNER=core, EXECUTOR_PIN=executor,
        OLD_MANIFEST=old_manifest, ORIGINAL_MANIFEST=old_manifest, OLD_PRIVATE_MANIFEST=old_private,
        DELTA_SPEC=delta_pin, GENERATION=report_pin, ROOT_BEFORE=ROOT_BEFORE, ROOT_AFTER=ROOT_AFTER,
        STATE_ROOT='/var/volatile/tmp/' + ROOT_AFTER, STATE_ALIAS='/tmp/' + ROOT_AFTER, RUNTIME_PREFIX=RUNTIME,
        CHANGED=CHANGED, PRIVATE_CHANGED=('mta_client_executor',), CHANGED_PAYLOAD_ROLES=CHANGED_PAYLOAD_ROLES,
        MECHANICAL_CLOSURE_COUNT=6, BUSINESS_CLOSURE_COUNT=2, FC_CHANGED=FC_CHANGED,
        PAYLOAD_BYTES=total, FILECENTER_BYTES=FILECENTER_BYTES, FILECENTER_CAP=FILECENTER_CAP,
        ORIGIN_SOURCE_PINS=source_pins, ORIGINAL_PAYLOAD_ROWS=original_payload,
        ORIGINAL_FILECENTER_ROWS=original_fc, ORDINARY_ROWS=rows, PRIVATE_ROWS=private_rows,
        MECHANICAL_EXPECTED=mechanical, FC_HTTP_EXPECTED=fc_business,
        BUSINESS_EXPECTED=literal_assignment(mother, 'BUSINESS_EXPECTED'),
        OWNER_BUSINESS_EXPECTED=literal_assignment(mother, 'OWNER_BUSINESS_EXPECTED'),
        MANIFEST_EXPECTED=manifests, DELTA_EXPECTED=spec, GENERATION_EXPECTED=report,
        ORIGINAL_MANIFEST_RAW=inputs[old_manifest[0]], OLD_PRIVATE_RAW=inputs[old_private[0]], **values)
    header = '\n'.join(('"""Flat receive FC HTTP cap graph; not device/phone/deadline acceptance."""',
        'import ast', 'import copy', 'import hashlib', 'import json', 'import os', 'from pathlib import Path',
        'import re', 'import stat', 'import types', '', 'BASE = Path(__file__).resolve().parents[1]') +
        tuple(name + ' = ' + repr(value) for name, value in constants.items()))
    reusable = '\n\n'.join(source_function(mother, name) for name in REUSED_FUNCTIONS)
    own_functions = '\n\n'.join(source_function(inputs[SELF], name) for name in ('validate_fc_http_delta', 'verify_inputs'))
    interfaces = '\n'.join(('SOURCE_PINS = ORIGIN_SOURCE_PINS', 'FILECENTER_SOURCE_PINS = FILECENTER_SOURCES',
        "TRIAL_FIELDS = frozenset(TRIAL_BOOL_FIELDS + ('claim_count', 'reason'))", 'json_bytes = jraw'))
    definitions = (header + '\n\n' + reusable + '\n\n' + interfaces + '\n\n' + own_functions + '\n').encode('ascii')
    ast.parse(definitions.decode('ascii'))
    outputs[DEFINITIONS] = definitions
    need(len(outputs) == 11 and len(source_pins) == report['source_origin_count'] and
         all(path.startswith(PREFIX) or path in (DEFINITIONS, MANIFEST_PATH, PRIVATE_MANIFEST_PATH) for path in outputs),
         'actual_eleven_output_partition')
    for path, raw in inputs.items():
        need(scoped(path).read_bytes() == raw, 'input_preserved_after_prepare')
    return outputs, report, inputs


def write_outputs(outputs, inputs):
    """One controlled publication; never replace an incompatible existing file."""
    need(type(outputs) is dict and len(outputs) == 11, 'eleven_outputs_required')
    destinations = {}
    for path, raw in outputs.items():
        need(type(raw) is bytes and (path.startswith(PREFIX) or
             path in (DEFINITIONS, MANIFEST_PATH, PRIVATE_MANIFEST_PATH)) and path != SELF,
             'output_namespace')
        target = scoped(path)
        if target.exists():
            need(stat.S_ISREG(target.lstat().st_mode) and target.read_bytes() == raw, 'existing_output_incompatible:' + path)
        destinations[path] = target
    for path, raw in inputs.items():
        need(scoped(path).read_bytes() == raw, 'input_preserved_before_write')
    created, retained = [], []
    for path, raw in outputs.items():
        target = destinations[path]
        if target.exists():
            need(scoped(path).read_bytes() == raw, 'retained_output_changed:' + path)
            retained.append(path)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target = scoped(path)
            with target.open('xb') as stream:
                need(stream.write(raw) == len(raw), 'exclusive_short_write')
            created.append(path)
        need(scoped(path).read_bytes() == raw, 'actual_output_readback:' + path)
    for path, raw in inputs.items():
        need(scoped(path).read_bytes() == raw, 'input_preserved_after_write')
    return created, retained


def main():
    args = sys.argv[1:]
    need(args in ([], ['--write']), 'source_plan_or_explicit_write')
    outputs, facts, inputs = prepare()
    if not args:
        print(json.dumps(dict(mode='SOURCE_PLAN_NO_WRITES', planned_output_bytes={path: len(raw) for path, raw in outputs.items()},
            payload_bytes=facts['payload_bytes'], remaining=facts['payload_remaining'],
            filecenter_bytes=facts['filecenter_bytes'], filecenter_remaining=facts['filecenter_remaining'],
            source_origin_count=facts['source_origin_count']), sort_keys=True))
        return 0
    created, retained = write_outputs(outputs, inputs)
    print(json.dumps(dict(mode='EXCL_OR_EXACT_EXISTING_OUTPUTS', created=created, retained_identical=retained,
        outputs=[list(pin(path, raw)) for path, raw in outputs.items()], payload_bytes=facts['payload_bytes'],
        remaining=facts['payload_remaining'], filecenter_bytes=facts['filecenter_bytes']), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
