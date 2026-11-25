"""Flat immutable headless75 graph for the one Owner dispatch change.

Default SOURCE plan writes nothing. Explicit --write creates eleven new files.
No previous main, assemble, verifier, test, build or device operation is run.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-owner-dispatch-graph-v1/'
RUNTIME = PREFIX + 'runtime/'
SELF = PREFIX + 'generate_graph.py'
DEFINITIONS = 'host/formal_receive_owner_dispatch_v1_definitions.py'
MANIFEST_PATH = 'host/formal_receive_owner_dispatch_v1_definition_manifest.json'
PRIVATE_MANIFEST_PATH = 'host/formal_receive_owner_dispatch_v1_private_source_manifest.json'
SPEC_PATH = PREFIX + 'graph-exactsource-delta.json'
REPORT_PATH = PREFIX + 'graph-generation.json'
MOTHER = ('host/formal_receive_publication_progress_v1_definitions.py', 123101,
          '3ae9820d752c9ed2d7ea582ece3ae6e248a9a69596e047e2a3dd5ed6ae294e49')
OWNER_INPUTS = (
    ('candidate/receive-owner-dispatch-v1/runtime/mta_client_service_owner.py', 107104,
     '22aa94d8d5ae2a1dd75c5c98635d80020b318f7071ea84c5c3cb3d85e2805adf'),
    ('candidate/receive-owner-dispatch-v1/generate.py', 9170,
     '0a1219c79bcf53283873a2c79128e0da6ec4d8330f50852adc126dfd46405b40'),
    ('candidate/receive-owner-dispatch-v1/exactsource-delta.json', 2189,
     '49d87f845578545103ab516c46a25e39a62dc3c0bd9003c205b42254ac7203dc'))
ROOT_BEFORE, ROOT_AFTER = 'p011-mta-rx-progress-v1', 'p011-mta-rx-dispatch-v1'
CHANGED = ('mta_client_executor', 'mta_client_receive_factory', 'mta_client_state_bridge',
           'mta_client_receive_boot', 'mta_client_service_owner')
CHANGED_PAYLOAD_ROLES = CHANGED + ('runtime35/mta_client_executor',)
INTERFACE_CONSTANTS = ('CHECKER', 'TRANSPORT', 'HELPERS', 'WPA', 'MONITOR', 'MODULE_NAMES',
                       'PRIVATE_MODULE_NAMES', 'TRIAL_BOOL_FIELDS', 'TRIAL_REASONS',
                       'TARGET_COMMON', 'TARGET_SERVICE', 'FILECENTER_SOURCES')
REUSED_FUNCTIONS = ('need', 'digest', 'jraw', 'scoped', 'read_pin', 'literal_assignment', 'replay',
                    'definition_rows', 'validate_delta', 'validate_runner', '_meta', 'load_checker',
                    '_short_chunks', 'parse_trial_facts', 'manifest_rows', 'make_source')


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


def validate_owner_business(inputs, entry):
    before, seed = inputs[entry['source'][0]], inputs[entry['candidate'][0]]
    need((len(before), digest(before)) == tuple(entry['source'][1:]) and
         (len(seed), digest(seed)) == tuple(entry['candidate'][1:]), 'dispatch_business_pins')
    edits = entry['edits']
    need(len(edits) == 1 and edits[0]['count'] == 1 and edits[0]['name'] == 'owner_context_dispatch' and
         edits[0]['before'] == owner_context(before) and edits[0]['after'] == owner_context(seed),
         'only_owner_context_business_block')
    need(replay(before, edits) == seed and replay(seed, edits, True) == before and
         len(seed) - len(before) == 78, 'owner_dispatch_complete_byte_inverse')
    delta = json.loads(inputs[entry['seed_delta'][0]].decode('ascii'))
    need(delta == entry['seed_delta_expected'] and delta['origin'] == dict(
         path=entry['source'][0], bytes=entry['source'][1], sha256=entry['source'][2]) and
         delta['candidate'] == dict(path=entry['candidate'][0], bytes=entry['candidate'][1],
                                    sha256=entry['candidate'][2]), 'actual_seed_delta_bindings')
    partial = [dict(row, name='seed_dispatch') for row in delta['replacements']]
    need(len(partial) == 1 and partial[0]['count'] == 1 and replay(before, partial) == seed and
         replay(seed, partial, True) == before, 'actual_seed_partial_byte_inverse')
    restored = replay(seed, edits, True)
    need(ast.dump(ast.parse(restored), include_attributes=True) == ast.dump(ast.parse(before), include_attributes=True),
         'owner_dispatch_complete_position_ast_inverse')


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


def load_inputs():
    need(len(OWNER_INPUTS) == 3 and len(ROOT_BEFORE) == len(ROOT_AFTER), 'frozen_owner_and_equal_root_required')
    inputs = {MOTHER[0]: read_pin(MOTHER)}
    rows = literal_assignment(inputs[MOTHER[0]], 'ORIGIN_SOURCE_PINS')
    need(len(rows) == 230, 'fixed_current_flat230')
    for row in rows + OWNER_INPUTS:
        inputs[row[0]] = read_pin(row)
    inputs[SELF] = scoped(SELF).read_bytes()
    return inputs


def assemble(inputs):
    """Pure derivation of actual bytes/pins from one flat input snapshot."""
    mother = inputs[MOTHER[0]]
    need((len(mother), digest(mother)) == MOTHER[1:] and len(OWNER_INPUTS) == 3, 'actual_current_mother_owner')
    origin_rows = literal_assignment(mother, 'ORIGIN_SOURCE_PINS')
    need(len(origin_rows) == 230, 'current230_fixed_inventory')
    for path, size, sha in origin_rows + OWNER_INPUTS:
        need((len(inputs[path]), digest(inputs[path])) == (size, sha), 'actual_flat_source_pin')
    values = {name: literal_assignment(mother, name) for name in INTERFACE_CONSTANTS}
    old_manifest, old_private, old_runner = (literal_assignment(mother, name) for name in ('MANIFEST', 'PRIVATE_MANIFEST', 'RUNNER'))
    ordinary, private = (json.loads(inputs[row[0]].decode('ascii')) for row in (old_manifest, old_private))
    old_rows = {row['module']: (row['path'], row['bytes'], row['sha256']) for row in ordinary['sources']}
    old_private_rows = tuple(('runtime35/' + r['module'], r['path'], r['bytes'], r['sha256']) for r in private['sources'])
    original_payload = tuple((r['module'], r['path'], r['bytes'], r['sha256']) for r in ordinary['sources']) + values['HELPERS'] + old_private_rows + (values['WPA'], values['MONITOR'])
    need(len(original_payload) == 75 and sum(r[2] for r in original_payload) == 4193272 and
         literal_assignment(mother, 'ROOT_AFTER') == ROOT_BEFORE, 'actual_current75_root_budget')
    owner_seed = OWNER_INPUTS[0]
    business = dict(source=list(old_rows['mta_client_service_owner']), candidate=list(owner_seed),
        seed_delta=list(OWNER_INPUTS[2]), seed_delta_expected=json.loads(inputs[OWNER_INPUTS[2][0]].decode('ascii')), edits=[dict(
        name='owner_context_dispatch', before=owner_context(inputs[old_rows['mta_client_service_owner'][0]]),
        after=owner_context(inputs[owner_seed[0]]), count=1)])
    validate_owner_business(inputs, business)
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
    need(executor[1] == old_rows['mta_client_executor'][1], 'equal_length_executor_root')
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
    boot_edits = [root('ROOT'), root('PHYSICAL_ROOT', True),
        assignment('CLIENT_MANIFEST_SHA', old_private[2], private_pin[2]),
        assignment('F37_SHA', old_rows['mta_client_executor'][2], executor[2]),
        source_tuple('mta_client_receive_factory', old_rows['mta_client_receive_factory'], new_pins['mta_client_receive_factory']),
        source_tuple('mta_client_state_bridge', old_rows['mta_client_state_bridge'], new_pins['mta_client_state_bridge'])]
    create('mta_client_receive_boot', old_rows['mta_client_receive_boot'], boot_edits, True)
    boot_raw = outputs[new_pins['mta_client_receive_boot'][0]]
    need(literal_assignment(boot_raw, 'F37_SHA') == executor[2] and
         ("    ('mta_client_executor', " + str(executor[1]) + ', F37_SHA),\n').encode('ascii') in boot_raw and
         ("SOURCE_PINS[0] != ('mta_client_executor', " + str(executor[1]) + ', F37_SHA)').encode('ascii') in boot_raw,
         'boot_table_and_source_shape_actual_executor')
    create('mta_client_service_owner', owner_seed, [root('ROOT'),
        assignment('BOOT_PIN', old_rows['mta_client_receive_boot'][1:], new_pins['mta_client_receive_boot'][1:]),
        dict(name='held_physical_root', before="        physical = '/var/volatile/tmp/" + ROOT_BEFORE + "'\n",
             after="        physical = '/var/volatile/tmp/" + ROOT_AFTER + "'\n", count=1)])
    ordinary_new, changes = copy.deepcopy(ordinary), []
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
         total == 4193272 + 78 <= 4194304 and len(mechanical) == 6, 'actual6_changed_69_exact_budget')
    for row, before in zip(payload, original_payload):
        if row[0] not in CHANGED_PAYLOAD_ROLES:
            need(row == before and inputs[row[1]] == inputs[before[1]], 'unchanged69_original_bytes')
    validate_runner(outputs[core[0]], rows, private_rows, values['HELPERS'], values['WPA'], values['MONITOR'])
    need(literal_assignment(outputs[executor[0]], 'MODULES') == values['PRIVATE_MODULE_NAMES'], 'executor35_order')
    factory_raw = outputs[new_pins['mta_client_receive_factory'][0]]
    need(literal_assignment(factory_raw, 'F_SHA') == executor[2] and
         factory_raw.count(("    ('mta_client_executor', " + str(executor[1]) + ', F_SHA),\n').encode('ascii')) == 1,
         'factory_actual_executor_row')
    manifests = [dict(source=list(old_manifest), candidate=list(manifest_pin), private=False, changes=changes),
        dict(source=list(old_private), candidate=list(private_pin), private=True,
             changes=[[private_index, private['sources'][private_index], private_new['sources'][private_index]]])]
    spec = dict(schema='p011-receive-owner-dispatch-v1-graph-delta', root=ROOT_AFTER,
        mechanical=mechanical, business=business, business_inputs=[list(row) for row in OWNER_INPUTS],
        manifests=manifests, changed_roles=list(changed), payload_bytes=total,
        unchanged_payload_roles=69, private_roles_exact=34, proc_native_fc9_unchanged=True)
    outputs[SPEC_PATH] = jraw(spec)
    need(len(outputs[SPEC_PATH]) <= 131072, 'finite_graph_delta_metadata')
    delta_pin = pin(SPEC_PATH, outputs[SPEC_PATH])
    origin = {path: pin(path, raw) for path, raw in inputs.items()}
    need(not set(origin).intersection(outputs), 'immutable_output_partition')
    origin.update((path, pin(path, raw)) for path, raw in outputs.items())
    report = dict(schema='p011-receive-owner-dispatch-v1-graph-generation',
        status='MECHANICALLY_DERIVED_NOT_NEW_DEVICE_TESTED', generator=list(pin(SELF, inputs[SELF])),
        source_origin_count=len(origin) + 1, mechanical_closure_count=6, business_closure_count=1,
        changed_payload_roles=list(changed), exact_payload_roles=69, private_roles_exact=34,
        payload_bytes=total, payload_remaining=4194304 - total, owner_business_growth=78,
        root=ROOT_AFTER, headless_only=True, navigation_ui_outputs=False, proc_native_fc9_unchanged=True,
        output_pins=[list(pin(path, raw)) for path, raw in sorted(outputs.items())], definitions_path=DEFINITIONS,
        definitions_and_report_pins_omitted_to_avoid_cycles=True, old_main_build_verify_called=False,
        old_tests_replayed=0, device_tested=False, phone_tested=False)
    outputs[REPORT_PATH] = jraw(report)
    report_pin = pin(REPORT_PATH, outputs[REPORT_PATH])
    origin[REPORT_PATH] = report_pin
    source_pins = tuple(origin[path] for path in sorted(origin))
    constants = dict(MOTHER=MOTHER, MANIFEST=manifest_pin, PRIVATE_MANIFEST=private_pin, RUNNER=core,
        EXECUTOR_PIN=executor, OLD_MANIFEST=old_manifest, ORIGINAL_MANIFEST=old_manifest, OLD_PRIVATE_MANIFEST=old_private,
        DELTA_SPEC=delta_pin, GENERATION=report_pin, ROOT_BEFORE=ROOT_BEFORE, ROOT_AFTER=ROOT_AFTER,
        STATE_ROOT='/var/volatile/tmp/' + ROOT_AFTER, STATE_ALIAS='/tmp/' + ROOT_AFTER,
        RUNTIME_PREFIX=RUNTIME, CHANGED=CHANGED, PRIVATE_CHANGED=('mta_client_executor',),
        CHANGED_PAYLOAD_ROLES=CHANGED_PAYLOAD_ROLES, MECHANICAL_CLOSURE_COUNT=6, BUSINESS_CLOSURE_COUNT=1,
        PAYLOAD_BYTES=total, ORIGIN_SOURCE_PINS=source_pins, ORIGINAL_PAYLOAD_ROWS=original_payload,
        ORDINARY_ROWS=rows, PRIVATE_ROWS=private_rows, MECHANICAL_EXPECTED=mechanical, BUSINESS_EXPECTED=business,
        MANIFEST_EXPECTED=manifests, DELTA_EXPECTED=spec, GENERATION_EXPECTED=report,
        ORIGINAL_MANIFEST_RAW=inputs[old_manifest[0]], OLD_PRIVATE_RAW=inputs[old_private[0]], **values)
    header = '\n'.join(('"""Flat headless Owner dispatch75 closure; not device/phone acceptance."""',
        'import ast', 'import copy', 'import hashlib', 'import json', 'import os', 'from pathlib import Path',
        'import re', 'import stat', 'import types', '', 'BASE = Path(__file__).resolve().parents[1]') +
        tuple(name + ' = ' + repr(value) for name, value in constants.items()))
    reusable = '\n\n'.join(source_function(mother, name) for name in REUSED_FUNCTIONS)
    business_functions = '\n\n'.join(source_function(inputs[SELF], name) for name in ('owner_context', 'validate_owner_business'))
    verify = source_function(mother, 'verify_inputs')
    anchor = '    for entry in MECHANICAL_EXPECTED:'
    need(verify.count(anchor) == 1, 'one_new_business_verifier_anchor')
    verify_new = verify.replace(anchor, '    validate_owner_business(inputs, BUSINESS_EXPECTED)\n' + anchor)
    need(verify_new.replace('    validate_owner_business(inputs, BUSINESS_EXPECTED)\n' + anchor, anchor) == verify,
         'complete_verifier_interface_inverse')
    interfaces = '\n'.join(('SOURCE_PINS = ORIGIN_SOURCE_PINS', 'FILECENTER_SOURCE_PINS = FILECENTER_SOURCES',
        "TRIAL_FIELDS = frozenset(TRIAL_BOOL_FIELDS + ('claim_count', 'reason'))", 'json_bytes = jraw'))
    definitions = (header + '\n\n' + reusable + '\n\n' + business_functions + '\n\n' + interfaces +
                   '\n\n' + verify_new + '\n').encode('ascii')
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
        print(json.dumps(dict(mode='SOURCE_PLAN_NO_WRITES', planned_output_bytes={p: len(r) for p, r in outputs.items()},
            payload_bytes=report['payload_bytes'], remaining=report['payload_remaining'],
            source_origin_count=report['source_origin_count']), sort_keys=True))
        return 0
    for path, raw in inputs.items():
        need(scoped(path).read_bytes() == raw, 'input_preserved_before_write')
    need(all(path.startswith(PREFIX) or path in (DEFINITIONS, MANIFEST_PATH, PRIVATE_MANIFEST_PATH)
             for path in outputs), 'explicit_eleven_output_namespace')
    need(all(not scoped(path).exists() for path in outputs), 'all_outputs_exclusive')
    for path, raw in outputs.items():
        target = scoped(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            need(stream.write(raw) == len(raw), 'exclusive_short_write')
        need(target.read_bytes() == raw, 'actual_output_readback')
    for path, raw in inputs.items():
        need(scoped(path).read_bytes() == raw, 'input_preserved_after_write')
    print(json.dumps(dict(mode='EXCL_ACTUAL_OUTPUTS', outputs=[list(pin(p, r)) for p, r in outputs.items()],
        payload_bytes=report['payload_bytes'], remaining=report['payload_remaining']), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
