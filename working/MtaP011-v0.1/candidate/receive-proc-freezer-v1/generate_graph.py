"""PC-only fresh seven-role Proc/freezer graph writer; no device or test entry.

The separately generated Proc and its two proof artifacts are read-only inputs.
Only its exact stable_key comparison masks PF_FREEZER_SKIP. Other changes are
mechanical independent-root/pin propagation from the current Window Runners and
atomic Worker. Existing definitions supply fixed interfaces, never their old
verify_inputs/main/suite. GUI20, the other 68 payload roles, FC9 and native assets
are reused byte-for-byte. This file does not create outputs without --write.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import types


BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-proc-freezer-v1/'
RUNTIME = PREFIX + 'runtime/'
SELF = PREFIX + 'generate_graph.py'
DEFINITIONS = 'host/formal_receive_proc_freezer_v1_definitions.py'
MANIFEST_PATH = 'host/formal_receive_proc_freezer_v1_definition_manifest.json'
PRIVATE_MANIFEST_PATH = 'host/formal_receive_proc_freezer_v1_private_source_manifest.json'
SPEC_PATH = PREFIX + 'graph-exactsource-delta.json'
REPORT_PATH = PREFIX + 'graph-generation.json'
ORIGINAL = ('host/formal_receive_durable_state_v1_definitions.py', 45031,
            'b98c66604bdb250820630f1844e5ea4b0af9bbd260e05388478034e37254e43b')
OLD_MANIFEST = ('host/formal_receive_durable_state_v1_definition_manifest.json', 7952,
                '2c9883367f8d61e0936ae7bf82841de04a59753795b908aada7ace5656bc6ebd')
OLD_PRIVATE_MANIFEST = ('host/formal_receive_durable_state_v1_private_source_manifest.json', 8169,
                        '7a11e023d97b5b54235e6cdf7d1a014f814b4ff5192a40e503d693d8a234cc0d')
OLD_CORE = ('candidate/receive-window-clock-v1/runtime/mta_formal_receive_session.py', 79279,
            '88c3dc8daac2f4315affb7f439e01a7a60a9c764053019fe9043f891b676a5aa')
OLD_NAVIGATION = ('candidate/receive-window-clock-v1/runtime/mta_formal_receive_navigation_session.py', 88850,
                  '2aa5c840d9df5293fe10d385060821269d5170da4261b751c49af091ccf31f48')
OLD_WORKER = ('candidate/receive-navigation-atomic-v1/runtime/ui_session.py', 100162,
              'cde8ae626632e5d86acb2cc741b7d22eb18582b58ed6d6fd48160c008b62225e')
GUI_VALIDATOR = ('candidate/formal-receive-durable-state-gui-v1/runtime/ui_assets.py', 12798,
                 '67e3d2d1bd7654cde6993d9746c8dd2cb3447676f0fb0f4bb2dec4a2ffb8d1bb')
PROC_SOURCE = ('candidate/client-proc-deadline-v25/runtime/mta_client_proc.py', 39384,
               'ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6')
PROC_CANDIDATE = (RUNTIME + 'mta_client_proc.py', 39398,
                  '2894a8ffb1e361bd1f4785e6da2b0df9e5ee8bff7711e21ee745ae3cd1f9653d')
PROC_GENERATOR = (PREFIX + 'generate_proc.py', 8164,
                  'c9e725dc092436a7c8fd82d84e38954dabac7cbf1571b2c736fd53fce55faad1')
PROC_DELTA = (PREFIX + 'proc-exactsource-delta.json', 1512,
              '0f047d009c25e068b7e260a53543273cc0ef83233f2f69eebccabbcc32088fc0')
PROC_GENERATION = (PREFIX + 'proc-generation.json', 1446,
                   'ba1887f08a17f6a04e02a8256719fadb40c2900fc63dbdc243f1cc00753304ad')
PROC_EDIT = dict(name='stable_key_masks_only_pf_freezer_skip', count=1,
    before='        return self.pid, self.start, self.comm, self.flags, self.ppid\n',
    after='        return self.pid, self.start, self.comm, self.flags & ~0x40000000, self.ppid\n')
PROC_GUARDS = dict(mask=1073741824, other_flags_bits_preserved=31,
    original_flags_and_raw_preserved=True, stable_key_line=120, return_line=121,
    actor_pass_line=484, identity_failure_line=524, parse_stat_unchanged=True,
    pf_kthread_checks_unchanged=True, boot_exe_cmdline_tasks_directory_checks_unchanged=True,
    deadlines_and_resource_accounting_unchanged=True, original_source_unchanged=True,
    device_executed=False, tests_executed=False, admission=False, restoration_verified=False)
ROOT_BEFORE = 'p011-mta-rx-durable-v1'
ROOT_AFTER = 'p011-mta-rx-freezer-v1'
CONTROL_BEFORE = '-receive-navigation-atomic-v1'
CONTROL_AFTER = '-receive-proc-freezer-v1'
SESSION = '559c72ccf8f8ff1b7fc83fb6'
CHANGED = ('mta_client_executor', 'mta_client_state_bridge',
           'mta_client_receive_factory', 'mta_client_receive_boot', 'mta_client_service_owner')
PRIVATE_CHANGED = ('mta_client_proc', 'mta_client_executor')
CHANGED_PAYLOAD_ROLES = CHANGED + tuple('runtime35/' + name for name in PRIVATE_CHANGED)
MECHANICAL_CLOSURE_COUNT = 8
BUSINESS_CLOSURE_COUNT = 1


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


def read_pin(source):
    raw = scoped(source[0]).read_bytes()
    need((len(raw), digest(raw)) == source[1:], 'graph_frozen_pin:' + source[0])
    return raw


def replay(raw, edits, inverse=False):
    need(type(edits) is list, 'graph_delta_edits')
    for row in reversed(edits) if inverse else edits:
        need(type(row) is dict and set(row) == {'name', 'before', 'after', 'count'} and
             type(row['name']) is str and type(row['before']) is str and type(row['after']) is str and
             row['before'] and row['after'] and row['before'] != row['after'] and
             type(row['count']) is int and row['count'] > 0, 'graph_delta_edit')
        before = row['after' if inverse else 'before'].encode('utf-8')
        after = row['before' if inverse else 'after'].encode('utf-8')
        need(raw.count(before) == row['count'], 'graph_exact_replay_count:' + row['name'])
        raw = raw.replace(before, after)
    return raw


def definition_rows(raw):
    text = raw.decode('utf-8')
    tree = ast.parse(text, feature_version=(3, 5))
    return tuple((type(node).__name__, node.name, node.lineno, node.end_lineno,
                  ast.get_source_segment(text, node)) for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.ClassDef)))


def validate_delta(before, after, edits, functions_unchanged=False):
    need(replay(before, edits) == after and replay(after, edits, True) == before, 'graph_complete_inverse')
    old_rows, new_rows = definition_rows(before), definition_rows(after)
    need(tuple(row[:4] for row in old_rows) == tuple(row[:4] for row in new_rows), 'graph_definition_lines')
    need(len(before.splitlines()) == len(after.splitlines()), 'graph_original_line_count')
    if functions_unchanged:
        need(old_rows == new_rows, 'graph_original_functions')


def literal_assignment(raw, name):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    nodes = [node for node in tree.body if isinstance(node, ast.Assign) and
             len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(nodes) == 1, 'graph_unique_assignment:' + name)
    return ast.literal_eval(nodes[0].value)


def validate_proc_artifacts(inputs):
    before, after = inputs[PROC_SOURCE[0]], inputs[PROC_CANDIDATE[0]]
    validate_delta(before, after, [PROC_EDIT])
    lines_before, lines_after = before.splitlines(keepends=True), after.splitlines(keepends=True)
    need(lines_before[120] == PROC_EDIT['before'].encode('ascii') and
         lines_after[120] == PROC_EDIT['after'].encode('ascii') and
         [index for index, pair in enumerate(zip(lines_before, lines_after)) if pair[0] != pair[1]] == [120],
         'graph_proc_only_return_line')
    tree = ast.parse(after.decode('ascii'), feature_version=(3, 5))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'StatIdentity']
    need(len(classes) == 1 and classes[0].lineno == 112, 'graph_proc_stat_identity')
    methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name == 'stable_key']
    expected = ast.parse('def stable_key(self):\n' + PROC_EDIT['after'], feature_version=(3, 5)).body[0]
    need(len(methods) == 1 and methods[0].lineno == 120 and
         ast.dump(methods[0], include_attributes=False) == ast.dump(expected, include_attributes=False),
         'graph_proc_exact_ast')
    delta_raw, report_raw = inputs[PROC_DELTA[0]], inputs[PROC_GENERATION[0]]
    delta, report = json.loads(delta_raw.decode('ascii')), json.loads(report_raw.decode('ascii'))
    need(delta == dict(schema='p011-receive-proc-freezer-v1-proc-delta',
        evidence='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=list(PROC_GENERATOR),
        source=list(PROC_SOURCE), candidate=list(PROC_CANDIDATE), replacements=[PROC_EDIT], guards=PROC_GUARDS),
        'graph_proc_delta_metadata')
    need(report == dict(schema='p011-receive-proc-freezer-v1-proc-generation',
        status='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=list(PROC_GENERATOR), source=list(PROC_SOURCE),
        outputs=[list(PROC_DELTA), list(PROC_CANDIDATE)], guards=PROC_GUARDS,
        host_checked=False, phone_tested=False), 'graph_proc_generation_metadata')


def validate_runner(raw, rows, private_rows, helpers, wpa, monitor):
    need(literal_assignment(raw, 'STATE_ROOT') == '/var/volatile/tmp/' + ROOT_AFTER and
         literal_assignment(raw, 'STATE_ALIAS') == '/tmp/' + ROOT_AFTER, 'graph_runner_roots')
    need(literal_assignment(raw, 'ROLE_PINS') == tuple((name, size, sha) for name, path, size, sha in rows) and
         literal_assignment(raw, 'PRIVATE_PINS') == tuple((name[len('runtime35/'):], size, sha)
                                                        for name, path, size, sha in private_rows) and
         literal_assignment(raw, 'HELPER_PINS') == tuple((name, size, sha) for name, path, size, sha in helpers) and
         literal_assignment(raw, 'WPA_PIN') == (wpa[0], wpa[2], wpa[3]) and
         literal_assignment(raw, 'MONITOR_PIN') == (monitor[0], monitor[2], monitor[3]), 'graph_runner_all_pins')


def validate_worker(raw, runner_pin):
    need(literal_assignment(raw, 'RUNNER_PIN') == runner_pin[1:] and
         literal_assignment(raw, 'VALIDATOR_PIN') == GUI_VALIDATOR[1:] and
         literal_assignment(raw, 'SESSION') == SESSION and
         literal_assignment(raw, 'STATE_ROOT') == '/var/volatile/tmp/' + ROOT_AFTER and
         literal_assignment(raw, 'STATE_ALIAS') == '/tmp/' + ROOT_AFTER, 'graph_worker_bindings')
    text = raw.decode('ascii')
    expected = "CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + " + repr(CONTROL_AFTER) + '\n'
    need(text.count(expected) == 1 and CONTROL_BEFORE not in text, 'graph_worker_exclusive_control')


def source_function(raw, name):
    text = raw.decode('utf-8')
    nodes = [node for node in ast.parse(text).body if isinstance(node, ast.FunctionDef) and node.name == name]
    need(len(nodes) == 1, 'graph_source_function:' + name)
    return ast.get_source_segment(text, nodes[0])


DEFINITION_TAIL = r'''

def manifest_rows(raw, private=False):
    value = json.loads(raw.decode('ascii'))
    original = json.loads((OLD_PRIVATE_RAW if private else ORIGINAL_MANIFEST_RAW).decode('ascii'))
    keys = {'schema', 'sources', 'previous_manifest_sha256'} if private else {'schema', 'sources'}
    need(type(value) is dict and set(value) == keys and value['schema'] == original['schema'] and
         type(value['sources']) is list and len(value['sources']) == 35 and
         (not private or value['previous_manifest_sha256'] == OLD_PRIVATE_MANIFEST[2]), 'freezer_manifest_shape')
    changed, result = (PRIVATE_CHANGED if private else CHANGED), []
    for row, before in zip(value['sources'], original['sources']):
        name = before['module']
        if name not in changed:
            need(row == before, 'freezer_unchanged_manifest_role')
        else:
            expected = PAYLOAD_CANDIDATE_PINS[name]
            need(row == dict(module=name, path=expected[0], bytes=expected[1], sha256=expected[2]) and
                 row['path'] == RUNTIME_PREFIX + name + '.py', 'freezer_changed_manifest_role')
        result.append(('runtime35/' + name if private else name, row['path'], row['bytes'], row['sha256']))
    names = tuple('runtime35/' + name for name in PRIVATE_MODULE_NAMES) if private else MODULE_NAMES
    need(tuple(row[0] for row in result) == names, 'freezer_manifest_role_order')
    return tuple(result)


def verify_inputs(inputs):
    """Verify only this exact delta; no historical verifier, test or runtime entry."""
    for path, size, sha in ORIGIN_SOURCE_PINS:
        raw = inputs[path]
        need((len(raw), digest(raw)) == (size, sha), 'freezer_origin_pin')
    for source in (MANIFEST, PRIVATE_MANIFEST, RUNNER, NAVIGATION_RUNNER, WORKER, DELTA_SPEC, GENERATION):
        raw = inputs[source[0]]
        need((len(raw), digest(raw)) == source[1:], 'freezer_candidate_pin')
    validate_proc_artifacts(inputs)
    need(inputs[OLD_MANIFEST[0]] == ORIGINAL_MANIFEST_RAW and
         inputs[OLD_PRIVATE_MANIFEST[0]] == OLD_PRIVATE_RAW, 'freezer_manifest_original')
    rows = manifest_rows(inputs[MANIFEST[0]])
    private = manifest_rows(inputs[PRIVATE_MANIFEST[0]], private=True)
    by_name = {name: (path, size, sha) for name, path, size, sha in rows}
    private_by_name = {name[len('runtime35/'):]: (path, size, sha) for name, path, size, sha in private}
    need(by_name['mta_client_executor'] == private_by_name['mta_client_executor'] == EXECUTOR_PIN and
         private_by_name['mta_client_proc'] == PROC_CANDIDATE and
         'mta_client_proc' not in by_name and 'mta_client_service_owner' not in private_by_name,
         'freezer_payload_domains')
    spec_raw = inputs[DELTA_SPEC[0]]
    need(len(spec_raw) <= 131072, 'freezer_delta_cap')
    spec = json.loads(spec_raw.decode('ascii'))
    need(type(spec) is dict and set(spec) == {'schema', 'evidence', 'root', 'business', 'mechanical',
         'manifests', 'guards', 'totals'} and
         spec['schema'] == 'p011-receive-proc-freezer-v1-graph-delta' and
         spec['evidence'] == 'MECHANICAL_GENERATED_NOT_HOST_CHECKED' and
         spec['root'] == {'before': ROOT_BEFORE, 'after': ROOT_AFTER} and
         spec['guards'] == FIXED_GUARDS and spec['totals'] == FIXED_TOTALS and
         spec['business'] == BUSINESS_EXPECTED and
         spec['mechanical'] == MECHANICAL_EXPECTED and
         spec['manifests'] == MANIFEST_EXPECTED, 'freezer_exact_delta_metadata')
    for entry in spec['business'] + spec['mechanical']:
        before_pin, after_pin = tuple(entry['source']), tuple(entry['candidate'])
        before, after = inputs[before_pin[0]], inputs[after_pin[0]]
        need((len(before), digest(before)) == before_pin[1:] and
             (len(after), digest(after)) == after_pin[1:], 'freezer_delta_entry_pins')
        validate_delta(before, after, entry['replacements'], entry.get('functions_unchanged', False))
    for entry, before_pin, after_pin, changes, is_private in zip(spec['manifests'],
            (OLD_MANIFEST, OLD_PRIVATE_MANIFEST), (MANIFEST, PRIVATE_MANIFEST),
            (CHANGED, PRIVATE_CHANGED), (False, True)):
        before = json.loads(inputs[before_pin[0]].decode('ascii'))
        after = json.loads(inputs[after_pin[0]].decode('ascii'))
        forward = json.loads(inputs[before_pin[0]].decode('ascii'))
        inverse = json.loads(inputs[after_pin[0]].decode('ascii'))
        need(entry['source'] == list(before_pin) and entry['candidate'] == list(after_pin) and
             entry['private'] is is_private and len(entry['changes']) == len(changes), 'freezer_manifest_delta')
        for row, name in zip(entry['changes'], changes):
            index = next(index for index, value in enumerate(before['sources']) if value['module'] == name)
            need(row == {'name': name, 'before': before['sources'][index], 'after': after['sources'][index]},
                 'freezer_manifest_delta_row')
            forward['sources'][index], inverse['sources'][index] = row['after'], row['before']
        if is_private:
            forward['previous_manifest_sha256'] = OLD_PRIVATE_MANIFEST[2]
            inverse['previous_manifest_sha256'] = before['previous_manifest_sha256']
        need(jraw(forward) == inputs[after_pin[0]] and jraw(inverse) == inputs[before_pin[0]],
             'freezer_manifest_complete_inverse')
    payload = rows + HELPERS + private + (WPA, MONITOR)
    need(len(payload) == len(ORIGINAL_PAYLOAD_ROWS) == 75, 'freezer_payload_count')
    total, changed, unchanged = 0, [], []
    for row, before in zip(payload, ORIGINAL_PAYLOAD_ROWS):
        name, path, size, sha = row
        raw = inputs[path]
        need(name == before[0] and (len(raw), digest(raw)) == (size, sha), 'freezer_payload_pin')
        total += len(raw)
        if name in CHANGED_PAYLOAD_ROLES:
            need(row != before, 'freezer_changed_role_present')
            changed.append(name)
        else:
            need(row == before and raw == inputs[before[1]], 'freezer_68_original_roles')
            unchanged.append(name)
    need(set(changed) == set(CHANGED_PAYLOAD_ROLES) and len(changed) == 7 and len(unchanged) == 68 and
         total == PAYLOAD_BYTES and total <= 4194304, 'freezer_payload_budget')
    for name, path, size, sha in FILECENTER_SOURCES:
        raw = inputs[path]
        need((len(raw), digest(raw)) == (size, sha), 'freezer_fc_original_pin')
    need(FILECENTER_SOURCES == FILECENTER_SOURCE_PINS and len(FILECENTER_SOURCES) == 9 and
         sum(row[2] for row in FILECENTER_SOURCES) == 113690 and
         sum(row[2] for row in FILECENTER_SOURCES) <= 131072, 'freezer_fc_original_budget')
    validate_runner(inputs[RUNNER[0]], rows, private, HELPERS, WPA, MONITOR)
    validate_runner(inputs[NAVIGATION_RUNNER[0]], rows, private, HELPERS, WPA, MONITOR)
    validate_worker(inputs[WORKER[0]], NAVIGATION_RUNNER)
    report = json.loads(inputs[GENERATION[0]].decode('ascii'))
    need(report['schema'] == 'p011-receive-proc-freezer-v1-graph-generation' and
         report['status'] == 'MECHANICAL_GENERATED_NOT_HOST_CHECKED' and
         report['source_origin_count'] == len(ORIGIN_SOURCE_PINS) and
         report['mechanical_closure_count'] == MECHANICAL_CLOSURE_COUNT == len(MECHANICAL_EXPECTED) and
         report['business_closure_count'] == BUSINESS_CLOSURE_COUNT == len(BUSINESS_EXPECTED) and
         report['guards'] == FIXED_GUARDS and report['totals'] == FIXED_TOTALS and
         report['artifacts_excluding_definitions_and_self'] == [list(value) for value in GENERATION_ARTIFACT_PINS],
         'freezer_generation_facts')
    return MECHANICAL_CLOSURE_COUNT
'''


def build():
    inputs = {}
    def load(source):
        raw = read_pin(source)
        need(source[0] not in inputs or inputs[source[0]] == raw, 'graph_input_conflict')
        inputs[source[0]] = raw
        return raw
    old_raw = load(ORIGINAL)
    old = types.ModuleType('fixed_durable_interfaces_for_freezer_graph')
    old.__file__ = str(BASE / ORIGINAL[0])
    # These frozen top-level definitions supply interfaces only. No old callable is executed.
    exec(compile(old_raw, old.__file__, 'exec'), old.__dict__)
    need(old.MANIFEST == OLD_MANIFEST and old.PRIVATE_MANIFEST == OLD_PRIVATE_MANIFEST and
         old.PAYLOAD_BYTES == 4191752 and len(old.ORIGIN_SOURCE_PINS) == 164, 'graph_current_interface_identity')
    manifest_raw, private_raw = load(OLD_MANIFEST), load(OLD_PRIVATE_MANIFEST)
    manifest, private = json.loads(manifest_raw.decode('ascii')), json.loads(private_raw.decode('ascii'))
    need(jraw(manifest) == manifest_raw and jraw(private) == private_raw, 'graph_original_manifest_serialization')
    old_rows = {row['module']: (row['path'], row['bytes'], row['sha256']) for row in manifest['sources']}
    old_private = {row['module']: (row['path'], row['bytes'], row['sha256']) for row in private['sources']}
    need(len(old_rows) == len(old_private) == 35 and old_private['mta_client_proc'] == PROC_SOURCE and
         old_rows['mta_client_executor'] == old_private['mta_client_executor'], 'graph_original_domains')
    for source in old.ORIGIN_SOURCE_PINS:
        load(source)
    for source in (OLD_CORE, OLD_NAVIGATION, OLD_WORKER, GUI_VALIDATOR,
                   PROC_SOURCE, PROC_CANDIDATE, PROC_GENERATOR, PROC_DELTA, PROC_GENERATION):
        load(source)
    validate_proc_artifacts(inputs)
    # New Proc is an actual already-generated input, never an output of this writer.
    proc_pin = pin(PROC_CANDIDATE[0], inputs[PROC_CANDIDATE[0]])
    need(proc_pin == PROC_CANDIDATE, 'graph_actual_proc_pin')
    new_pins = {'mta_client_proc': proc_pin}
    outputs, mechanical = {}, []

    def create(name, source_pin, changes, functions_unchanged=False):
        before = load(source_pin)
        edits = [dict(name=label, before=prior, after=after, count=count)
                 for label, prior, after, count in changes]
        raw = replay(before, edits)
        validate_delta(before, raw, edits, functions_unchanged)
        path = RUNTIME + name + '.py'
        need(path not in outputs and path != PROC_CANDIDATE[0], 'graph_unique_output')
        outputs[path] = raw
        new_pins[name] = pin(path, raw)
        mechanical.append(dict(name=name, source=list(source_pin), candidate=list(new_pins[name]),
                               replacements=edits, functions_unchanged=functions_unchanged))

    def assignment(label, name, before, after):
        return label, name + ' = ' + repr(before) + '\n', name + ' = ' + repr(after) + '\n', 1

    def root_assignment(name, physical=False):
        prefix = '/var/volatile/tmp/' if physical else '/tmp/'
        return assignment(name + '_isolation_root', name, prefix + ROOT_BEFORE, prefix + ROOT_AFTER)

    def tuple_change(name, before, after, count=1):
        return (name + '_source_tuple', '    ' + repr((name,) + before[1:]) + ',\n',
                '    ' + repr((name,) + after[1:]) + ',\n', count)

    create('mta_client_executor', old_rows['mta_client_executor'], (
        ('private_runtime_isolation_root',
         "    if (directory != '/var/volatile/tmp/" + ROOT_BEFORE + "/runtime35' and\n",
         "    if (directory != '/var/volatile/tmp/" + ROOT_AFTER + "/runtime35' and\n", 1),))
    need(new_pins['mta_client_executor'][1] == old_rows['mta_client_executor'][1], 'graph_executor_same_length')
    create('mta_client_state_bridge', old_rows['mta_client_state_bridge'], (
        assignment('executor_parent_sha', 'PARENT_SOURCE_SHA', old_rows['mta_client_executor'][2],
                   new_pins['mta_client_executor'][2]),), functions_unchanged=True)

    def bind_manifest(value, names, is_private):
        result, changes = copy.deepcopy(value), []
        for name in names:
            index = next(index for index, row in enumerate(result['sources']) if row['module'] == name)
            before = dict(result['sources'][index])
            path, size, sha = new_pins[name]
            after = dict(module=name, path=path, bytes=size, sha256=sha)
            result['sources'][index] = after
            changes.append(dict(name=name, before=before, after=after))
        if is_private:
            result['previous_manifest_sha256'] = OLD_PRIVATE_MANIFEST[2]
        return result, changes

    private_new, private_changes = bind_manifest(private, PRIVATE_CHANGED, True)
    outputs[PRIVATE_MANIFEST_PATH] = jraw(private_new)
    private_pin = pin(PRIVATE_MANIFEST_PATH, outputs[PRIVATE_MANIFEST_PATH])
    create('mta_client_receive_factory', old_rows['mta_client_receive_factory'], (
        root_assignment('ASSET_ROOT'), root_assignment('ASSET_PHYSICAL_ROOT', True),
        assignment('private_manifest_sha', 'SOURCE_MANIFEST_SHA', OLD_PRIVATE_MANIFEST[2], private_pin[2]),
        assignment('executor_sha', 'F_SHA', old_rows['mta_client_executor'][2], new_pins['mta_client_executor'][2]),
        tuple_change('mta_client_proc', PROC_SOURCE, proc_pin)), functions_unchanged=True)
    create('mta_client_receive_boot', old_rows['mta_client_receive_boot'], (
        root_assignment('ROOT'), root_assignment('PHYSICAL_ROOT', True),
        assignment('private_manifest_sha', 'CLIENT_MANIFEST_SHA', OLD_PRIVATE_MANIFEST[2], private_pin[2]),
        assignment('executor_sha', 'F37_SHA', old_rows['mta_client_executor'][2], new_pins['mta_client_executor'][2]),
        tuple_change('mta_client_receive_factory', old_rows['mta_client_receive_factory'],
                     new_pins['mta_client_receive_factory']),
        tuple_change('mta_client_state_bridge', old_rows['mta_client_state_bridge'],
                     new_pins['mta_client_state_bridge'])), functions_unchanged=True)
    create('mta_client_service_owner', old_rows['mta_client_service_owner'], (
        root_assignment('ROOT'),
        ('held_physical_isolation_root', "        physical = '/var/volatile/tmp/" + ROOT_BEFORE + "'\n",
         "        physical = '/var/volatile/tmp/" + ROOT_AFTER + "'\n", 1),
        assignment('boot_pin', 'BOOT_PIN', old_rows['mta_client_receive_boot'][1:],
                   new_pins['mta_client_receive_boot'][1:])))
    manifest_new, manifest_changes = bind_manifest(manifest, CHANGED, False)
    outputs[MANIFEST_PATH] = jraw(manifest_new)
    manifest_pin = pin(MANIFEST_PATH, outputs[MANIFEST_PATH])
    rows = tuple((row['module'], row['path'], row['bytes'], row['sha256']) for row in manifest_new['sources'])
    private_rows = tuple(('runtime35/' + row['module'], row['path'], row['bytes'], row['sha256'])
                         for row in private_new['sources'])
    runner_changes = [root_assignment('STATE_ROOT', True), root_assignment('STATE_ALIAS')]
    runner_changes += [tuple_change(name, old_rows[name], new_pins[name],
                                   2 if name == 'mta_client_executor' else 1) for name in CHANGED]
    runner_changes.append(tuple_change('mta_client_proc', PROC_SOURCE, proc_pin))
    create('mta_formal_receive_session', OLD_CORE, runner_changes, functions_unchanged=True)
    create('mta_formal_receive_navigation_session', OLD_NAVIGATION, runner_changes, functions_unchanged=True)
    core_pin = new_pins['mta_formal_receive_session']
    navigation_pin = new_pins['mta_formal_receive_navigation_session']
    create('ui_session', OLD_WORKER, (
        assignment('navigation_runner_pin', 'RUNNER_PIN', OLD_NAVIGATION[1:], navigation_pin[1:]),
        root_assignment('STATE_ROOT', True), root_assignment('STATE_ALIAS'),
        ('exclusive_control_suffix',
         "CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + " + repr(CONTROL_BEFORE) + '\n',
         "CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + " + repr(CONTROL_AFTER) + '\n', 1)),
        functions_unchanged=True)
    worker_pin = new_pins['ui_session']
    need(len(mechanical) == MECHANICAL_CLOSURE_COUNT == 8, 'graph_mechanical_count')
    validate_runner(outputs[core_pin[0]], rows, private_rows, old.HELPERS, old.WPA, old.MONITOR)
    validate_runner(outputs[navigation_pin[0]], rows, private_rows, old.HELPERS, old.WPA, old.MONITOR)
    validate_worker(outputs[worker_pin[0]], navigation_pin)
    original_rows = tuple((row['module'], row['path'], row['bytes'], row['sha256']) for row in manifest['sources'])
    original_private = tuple(('runtime35/' + row['module'], row['path'], row['bytes'], row['sha256'])
                             for row in private['sources'])
    original_payload = original_rows + old.HELPERS + original_private + (old.WPA, old.MONITOR)
    payload = rows + old.HELPERS + private_rows + (old.WPA, old.MONITOR)
    need(len(original_payload) == len(payload) == 75 and
         sum(row[2] for row in original_payload) == 4191752, 'graph_original_payload_budget')
    total, changed_roles, unchanged_roles = 0, [], []
    for row, before_row in zip(payload, original_payload):
        name, path, size, sha = row
        before_raw = load(before_row[1:])
        raw = outputs[path] if path in outputs else load((path, size, sha))
        need(name == before_row[0] and (len(raw), digest(raw)) == (size, sha), 'graph_payload_pin')
        total += len(raw)
        if name in CHANGED_PAYLOAD_ROLES:
            need(row != before_row, 'graph_changed_role_present')
            changed_roles.append(name)
        else:
            need(row == before_row and raw == before_raw, 'graph_68_unchanged_roles')
            unchanged_roles.append(name)
    need(set(changed_roles) == set(CHANGED_PAYLOAD_ROLES) and len(changed_roles) == 7 and
         len(unchanged_roles) == 68 and total <= 4194304, 'graph_payload_budget')
    need(old.FILECENTER_SOURCES == old.FILECENTER_SOURCE_PINS and len(old.FILECENTER_SOURCES) == 9 and
         sum(row[2] for row in old.FILECENTER_SOURCES) == 113690, 'graph_fc_identity')
    for name, path, size, sha in old.FILECENTER_SOURCES:
        load((path, size, sha))
    guards = dict(payload_role_count=75, ordinary_count=35, private_count=35,
        changed_payload_roles=7, unchanged_payload_roles=68, ordinary_changed_roles=5, private_changed_roles=2,
        payload_cap=4194304, filecenter_count=9, filecenter_cap=131072,
        target_source_cap=2097152, headless_line_cap=256, ui_line_cap=2048, wire_cap=6291456,
        startup_seconds=10, prepare_seconds=120, owner_seconds=600, cleanup_seconds=60,
        navigation_display_seconds=20, ready_seconds=10, startup_remote_alarm_seconds=240,
        startup_host_seconds=250, worker_run_fixed_line=1246, navigation_failure_line=1560,
        navigation_observer_line=817, original_result_fields=51,
        proc_mask=1073741824, client_rfinit_unchanged=True, current_window_logic_unchanged=True,
        atomic_functions_unchanged=True, gui20_unchanged=True, native_unchanged=True, filecenter_unchanged=True,
        historical_verifier_called=False, historical_generator_called=False, tests_executed=False,
        source_check_executed=False, device_tested=False, rf_started=False,
        phone_tested=False, restoration_verified=False)
    totals = dict(payload_bytes=total, payload_remaining=4194304 - total,
                  original_payload_bytes=4191752, filecenter_bytes=113690)
    business = [dict(name='mta_client_proc', source=list(PROC_SOURCE), candidate=list(proc_pin),
                     proof=list(PROC_DELTA), generation=list(PROC_GENERATION), replacements=[PROC_EDIT])]
    manifests = [dict(source=list(OLD_MANIFEST), candidate=list(manifest_pin),
                      changes=manifest_changes, private=False),
                 dict(source=list(OLD_PRIVATE_MANIFEST), candidate=list(private_pin),
                      changes=private_changes, private=True)]
    spec = dict(schema='p011-receive-proc-freezer-v1-graph-delta',
        evidence='MECHANICAL_GENERATED_NOT_HOST_CHECKED', root=dict(before=ROOT_BEFORE, after=ROOT_AFTER),
        business=business, mechanical=mechanical, manifests=manifests, guards=guards, totals=totals)
    outputs[SPEC_PATH] = jraw(spec)
    need(len(outputs[SPEC_PATH]) <= 131072, 'graph_delta_cap')
    delta_pin = pin(SPEC_PATH, outputs[SPEC_PATH])
    generator_raw = scoped(SELF).read_bytes()
    generator_pin = pin(SELF, generator_raw)
    inputs[SELF] = generator_raw
    # Include every actual dependency and new artifact needed by the caller's flat input reader.
    origin = {path: pin(path, raw) for path, raw in inputs.items()}
    for path, raw in outputs.items():
        need(path not in origin, 'graph_origin_output_collision')
        origin[path] = pin(path, raw)
    artifact_pins = tuple(pin(path, raw) for path, raw in sorted(outputs.items()))
    report = dict(schema='p011-receive-proc-freezer-v1-graph-generation',
        status='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=list(generator_pin),
        proc_inputs=[list(value) for value in (PROC_SOURCE, proc_pin, PROC_GENERATOR, PROC_DELTA, PROC_GENERATION)],
        source_origin_count=len(origin) + 1, mechanical_closure_count=MECHANICAL_CLOSURE_COUNT,
        business_closure_count=BUSINESS_CLOSURE_COUNT,
        ordinary_changed_roles=list(CHANGED), private_changed_roles=list(PRIVATE_CHANGED),
        unchanged_payload_roles=unchanged_roles, guards=guards, totals=totals,
        artifacts_excluding_definitions_and_self=[list(value) for value in artifact_pins],
        definitions_path=DEFINITIONS, generation_path=REPORT_PATH,
        definitions_and_self_omitted_to_avoid_circular_pins=True,
        host_checked=False, tests_executed=False, device_tested=False, phone_tested=False)
    outputs[REPORT_PATH] = jraw(report)
    report_pin = pin(REPORT_PATH, outputs[REPORT_PATH])
    origin[REPORT_PATH] = report_pin
    source_pins = tuple(origin[path] for path in sorted(origin))
    need(len(source_pins) == report['source_origin_count'], 'graph_origin_count')
    payload_pins = {name: new_pins[name] for name in CHANGED + ('mta_client_proc',)}
    constants = dict(ORIGINAL=ORIGINAL, MANIFEST=manifest_pin, PRIVATE_MANIFEST=private_pin,
        RUNNER=core_pin, NAVIGATION_RUNNER=navigation_pin, WORKER=worker_pin,
        EXECUTOR_PIN=new_pins['mta_client_executor'], DELTA_SPEC=delta_pin, GENERATION=report_pin,
        GENERATOR_PIN=generator_pin, OLD_MANIFEST=OLD_MANIFEST, OLD_PRIVATE_MANIFEST=OLD_PRIVATE_MANIFEST,
        PROC_SOURCE=PROC_SOURCE, PROC_CANDIDATE=proc_pin, PROC_GENERATOR=PROC_GENERATOR,
        PROC_DELTA=PROC_DELTA, PROC_GENERATION=PROC_GENERATION, PROC_EDIT=PROC_EDIT, PROC_GUARDS=PROC_GUARDS,
        GUI_VALIDATOR=GUI_VALIDATOR, SESSION=SESSION, CONTROL_BEFORE=CONTROL_BEFORE, CONTROL_AFTER=CONTROL_AFTER,
        ROOT_BEFORE=ROOT_BEFORE, ROOT_AFTER=ROOT_AFTER, RUNTIME_PREFIX=RUNTIME,
        STATE_ROOT='/var/volatile/tmp/' + ROOT_AFTER, STATE_ALIAS='/tmp/' + ROOT_AFTER,
        CHANGED=CHANGED, PRIVATE_CHANGED=PRIVATE_CHANGED, CHANGED_PAYLOAD_ROLES=CHANGED_PAYLOAD_ROLES,
        MECHANICAL_CLOSURE_COUNT=MECHANICAL_CLOSURE_COUNT, BUSINESS_CLOSURE_COUNT=BUSINESS_CLOSURE_COUNT,
        PAYLOAD_BYTES=total, FIXED_GUARDS=guards, FIXED_TOTALS=totals,
        ORIGIN_SOURCE_PINS=source_pins, SOURCE_PINS=source_pins,
        PAYLOAD_CANDIDATE_PINS=payload_pins, ORIGINAL_PAYLOAD_ROWS=original_payload,
        BUSINESS_EXPECTED=business, MECHANICAL_EXPECTED=mechanical, MANIFEST_EXPECTED=manifests,
        GENERATION_ARTIFACT_PINS=artifact_pins)
    header = '\n'.join(('"""Flat exact Proc/freezer source closure; not device or phone acceptance."""',
        'import ast', 'import hashlib', 'import json', 'from pathlib import Path', 'import types', '',
        'BASE = Path(__file__).resolve().parents[1]') +
        tuple(name + ' = ' + repr(value) for name, value in constants.items()))
    reusable = '\n\n'.join(source_function(generator_raw, name) for name in (
        'need', 'digest', 'jraw', 'scoped', 'read_pin', 'replay', 'definition_rows', 'validate_delta',
        'literal_assignment', 'validate_proc_artifacts', 'validate_runner', 'validate_worker'))
    interfaces = '\n'.join((
        'ORIGINAL_RAW = read_pin(ORIGINAL)',
        "_old = types.ModuleType('fixed_durable_interfaces_for_freezer_definitions')",
        '_old.__file__ = str(BASE / ORIGINAL[0])',
        "exec(compile(ORIGINAL_RAW, _old.__file__, 'exec'), _old.__dict__)",
        'CHECKER, TRANSPORT = _old.CHECKER, _old.TRANSPORT',
        'BASE_ORIGINAL, BASE_ORIGINAL_RAW = _old.BASE_ORIGINAL, _old.BASE_ORIGINAL_RAW',
        'HELPERS, WPA, MONITOR = _old.HELPERS, _old.WPA, _old.MONITOR',
        'MODULE_NAMES, PRIVATE_MODULE_NAMES = _old.MODULE_NAMES, _old.PRIVATE_MODULE_NAMES',
        'TRIAL_BOOL_FIELDS, TRIAL_REASONS, TRIAL_FIELDS = _old.TRIAL_BOOL_FIELDS, _old.TRIAL_REASONS, _old.TRIAL_FIELDS',
        'TARGET_COMMON, TARGET_SERVICE = _old.TARGET_COMMON, _old.TARGET_SERVICE',
        'load_checker, _short_chunks = _old.load_checker, _old._short_chunks',
        'parse_trial_facts = _old.parse_trial_facts',
        'FILECENTER_SOURCES = _old.FILECENTER_SOURCES', 'FILECENTER_SOURCE_PINS = FILECENTER_SOURCES',
        'ORIGINAL_MANIFEST = OLD_MANIFEST',
        'ORIGINAL_MANIFEST_RAW = read_pin(OLD_MANIFEST)', 'OLD_PRIVATE_RAW = read_pin(OLD_PRIVATE_MANIFEST)',
        'json_bytes = jraw', ''))
    definitions_raw = (header + '\n\n' + reusable + '\n\n' + interfaces + DEFINITION_TAIL +
                       '\n\n' + source_function(old_raw, 'make_source') + '\n').encode('utf-8')
    ast.parse(definitions_raw.decode('utf-8'), filename=DEFINITIONS)
    outputs[DEFINITIONS] = definitions_raw
    need(len(outputs) == 13 and not any(path in outputs for path in
         (PROC_CANDIDATE[0], PROC_DELTA[0], PROC_GENERATION[0], PROC_GENERATOR[0])), 'graph_output_partition')
    for source in source_pins:
        if source[0] not in outputs:
            need(read_pin(source) == inputs[source[0]], 'graph_input_snapshot')
    return outputs, report, inputs


def main():
    need(sys.argv[1:] == ['--write'], 'explicit_fresh_graph_write_required')
    outputs, report, inputs = build()
    allowed_host = {DEFINITIONS, MANIFEST_PATH, PRIVATE_MANIFEST_PATH}
    # All destinations are checked before the first write. A partial failure is retained.
    for path in outputs:
        target = scoped(path)
        need((path.startswith(PREFIX) or path in allowed_host) and
             not target.exists(), 'fresh_graph_output:' + path)
    for path, original in inputs.items():
        need(scoped(path).read_bytes() == original, 'graph_input_before_write:' + path)
    for path, raw in outputs.items():
        target = scoped(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as handle:
            need(handle.write(raw) == len(raw), 'graph_short_write')
        need(target.read_bytes() == raw, 'graph_output_readback:' + path)
    for path, original in inputs.items():
        need(scoped(path).read_bytes() == original, 'graph_input_after_write:' + path)
    print(json.dumps(dict(status=report['status'], output_count=len(outputs),
        source_origin_count=report['source_origin_count'], mechanical_closure_count=MECHANICAL_CLOSURE_COUNT,
        business_closure_count=BUSINESS_CLOSURE_COUNT, totals=report['totals'],
        outputs=[list(pin(path, raw)) for path, raw in sorted(outputs.items())],
        host_checked=False, tests_executed=False, device_tested=False), sort_keys=True))


if __name__ == '__main__':
    main()
