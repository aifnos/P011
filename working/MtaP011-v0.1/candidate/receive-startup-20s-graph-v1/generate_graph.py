"""Independent authorized 20s preparation graph; original 10s history stays exact.

prepare() returns (outputs, facts, inputs), only reading and deriving bytes.
Explicit --write preflights all destinations, then publishes EXCL or accepts
exact existing bytes. This never invokes an old generator/verify/main, a test,
subprocess, ADB, device, RF, send graph, or UI. The device root is not certified.
Only the pinned mother's pure mechanical helpers are loaded by AST selection.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import stat
import sys
import types

BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-startup-20s-graph-v1/'
RUNTIME = PREFIX + 'runtime/'
SELF = PREFIX + 'generate_graph.py'
DEFINITIONS = 'host/formal_receive_startup_20s_v1_definitions.py'
MANIFEST_PATH = 'host/formal_receive_startup_20s_v1_definition_manifest.json'
PRIVATE_MANIFEST_PATH = 'host/formal_receive_startup_20s_v1_private_source_manifest.json'
SPEC_PATH = PREFIX + 'graph-exactsource-delta.json'
REPORT_PATH = PREFIX + 'graph-generation.json'
MOTHER = ('host/formal_receive_profile_cache_v1_definitions.py', 276517,
          'fc1327b17f4124e286b967b3246f59c69458b803834efb34fd56246350bb5043')
GENERATOR_MOTHER = ('candidate/receive-profile-cache-graph-v1/generate_graph.py', 37744,
                    'f6d2ad0ec343b01a126e60492a2144038d4c3ada16e1f4719abb8ca06857326a')
MECHANICAL_HELPERS = ('candidate/receive-fc-http-cap-graph-v1/generate_graph.py', 31875,
                      '15f7f9569f0513c6c7cc15158fe3e24b84875b9ab7d7fb9f5ef48c6d1c3bd0bd')
# Actual Root-published seed; its generator is provenance, never executed here.
PREPARE_SEED = ('candidate/receive-startup-20s-v1/runtime/mta_client_receive_factory.py', 99675,
                '32784fee80f5e74d8e49e4a517e5dc5d45f297c0ad2f5bad42b343b81872da4d')
PREPARE_DELTA = ('candidate/receive-startup-20s-v1/exactsource-delta.json', 1823,
                 '935415b58c9ee53ac860398bd89819eac6a1a9e8492cb9ad9bdd7b81823c4a3f')
PREPARE_GENERATOR = ('candidate/receive-startup-20s-v1/generate_seed.py', 8560,
                     '313186ad15e4a6eb6c8d148c08a99044c572f7bb105b2fd8ade774214e11f84c')
ROOT_BEFORE = 'p011-mta-rx-pfcache-v01'
ROOT_AFTER = 'p011-mta-rx-prep20-v001'
CHANGED = ('mta_client_executor', 'mta_client_receive_factory', 'mta_client_state_bridge',
           'mta_client_receive_boot', 'mta_client_service_owner')
CHANGED_PAYLOAD_ROLES = CHANGED + ('runtime35/mta_client_executor',)
MOTHER_PAYLOAD_BYTES = 4193768
PAYLOAD_CAP = 4194304
FILECENTER_BYTES = 113832
FILECENTER_CAP = 131072
CACHE_BYTE_CAP = 500
INTERFACE_CONSTANTS = ('CHECKER', 'TRANSPORT', 'HELPERS', 'WPA', 'MONITOR', 'MODULE_NAMES',
                       'PRIVATE_MODULE_NAMES', 'TRIAL_BOOL_FIELDS', 'TRIAL_REASONS',
                       'TARGET_COMMON', 'TARGET_SERVICE', 'FILECENTER_SOURCES')
HELPER_FUNCTIONS = ('owner_context', 'replay', 'definition_rows', 'validate_delta',
                    'assignment', 'source_tuple', 'validate_runner')
REUSED_FUNCTIONS = ('need', 'digest', 'jraw', 'scoped', 'read_pin', 'literal_assignment',
                    'replay', 'definition_rows', 'validate_delta', 'validate_runner',
                    '_meta', 'load_checker', '_short_chunks', 'parse_trial_facts',
                    'manifest_rows', 'make_source', 'owner_context', 'validate_owner_business',
                    'scope_originals', 'validate_scope_business', 'validate_fc_http_delta',
                    'cache_target', 'remove_cache_assignments')
MOTHER_OUTPUT_PINS = (
    ('candidate/receive-profile-cache-graph-v1/graph-exactsource-delta.json', 44462,
     '8d02404d084ca90f9c044fa6eced2bb6c41eeabfffb986d18e302b2869db91a3'),
    ('candidate/receive-profile-cache-graph-v1/runtime/mta_client_executor.py', 124769,
     '65e5d26f411fbdf71e583bf7f344d664d7934bc2b33260197ed5fa3279182015'),
    ('candidate/receive-profile-cache-graph-v1/runtime/mta_client_receive_boot.py', 19697,
     'd8f62bd0f00840c5f210dabe211c827bf2c396f5b6075019032de2f688ee744f'),
    ('candidate/receive-profile-cache-graph-v1/runtime/mta_client_receive_factory.py', 99675,
     '3f0ca3d039301a221fce10b5b72cb50e0bf6d374298656879ff748de61ec5cf5'),
    ('candidate/receive-profile-cache-graph-v1/runtime/mta_client_service_owner.py', 107104,
     'e135dc8f7cbd32c7b9430dbbdfe83586bbe13510cbc5180bdff7cd076128a83b'),
    ('candidate/receive-profile-cache-graph-v1/runtime/mta_client_state_bridge.py', 21356,
     '3a52e050465595befa564c45db75bcfde015248f0072529db4165fe7a1c0066a'),
    ('candidate/receive-profile-cache-graph-v1/runtime/mta_formal_receive_session.py', 79281,
     '444922ee9cc41781b497e8f0dce82095da4ea8fbcd297e5c91448da1ad34f967'),
    ('host/formal_receive_profile_cache_v1_definition_manifest.json', 7947,
     '44993c2d82a9096c884104906d60447b1d389f673a1c489c9768bfdcf31f1c2b'),
    ('host/formal_receive_profile_cache_v1_private_source_manifest.json', 8167,
     '05b2dca4b0504366202c26600fc1ea2d2974b4d2104cc96df587c5c9d954b6a5'),
    ('candidate/receive-profile-cache-graph-v1/graph-generation.json', 3728,
     'c2da0bbbb53fae4768a3ded155619d03935f2aac4c31582b701cb786a39c8e91'),
    MOTHER)


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


def pure_helpers(raw):
    """Only seven audited FunctionDefs; no mother imports/assignments/main."""
    text = '\n\n'.join(source_function(raw, name) for name in HELPER_FUNCTIONS)
    module = types.ModuleType('fixed_receive_profile_cache_mechanical_helpers')
    module.__dict__.update(ast=ast, need=need, ROOT_AFTER=ROOT_AFTER,
                           literal_assignment=literal_assignment)
    exec(compile(text, '<fixed-profile-cache-mechanical-helpers>', 'exec'), module.__dict__)
    need(tuple(node.name for node in ast.parse(text).body) == HELPER_FUNCTIONS,
         'exact_seven_mechanical_helper_definitions')
    return module


def profile_method(raw):
    text = raw.decode('ascii')
    rows = [node for node in ast.parse(text, feature_version=(3, 5)).body
            if isinstance(node, ast.FunctionDef) and node.name == '_live_profile']
    need(len(rows) == 1, 'one_actual_live_profile')
    return ast.get_source_segment(text, rows[0])


def validate_profile_business(inputs, entry):
    """One complete DATA method inverse, independently of inherited business."""
    before, seed = inputs[entry['source'][0]], inputs[entry['candidate'][0]]
    need((len(before), digest(before)) == tuple(entry['source'][1:]) and
         (len(seed), digest(seed)) == tuple(entry['candidate'][1:]), 'cache_business_pins')
    edits = entry['edits']
    need(type(edits) is list and len(edits) == 1 and edits[0]['count'] == 1 and
         edits[0]['name'] == 'live_profile_private_data_cache' and
         edits[0]['before'] == profile_method(before) and edits[0]['after'] == profile_method(seed),
         'cache_only_complete_live_profile')
    restored = replay(seed, edits, True)
    need(replay(before, edits) == seed and restored == before and
         0 < len(seed) - len(before) == entry['byte_delta'] <= CACHE_BYTE_CAP,
         'cache_complete_byte_inverse_and_budget')
    need(ast.dump(ast.parse(restored), include_attributes=True) ==
         ast.dump(ast.parse(before), include_attributes=True), 'cache_complete_position_ast_inverse')
    old, new = definition_rows(before), definition_rows(seed)
    need(tuple((row[0], row[1]) for row in old) == tuple((row[0], row[1]) for row in new),
         'cache_same_definition_inventory')
    changed = []
    for original, current in zip(old, new):
        if original[4] != current[4]:
            changed.append((original[0], original[1]))
    need(changed == [('FunctionDef', '_live_profile')], 'cache_all_other_definition_bytes_exact')
    delta = json.loads(inputs[entry['seed_delta'][0]].decode('ascii'))
    need(delta == entry['seed_delta_expected'] and delta['origin'] == dict(
         path=entry['source'][0], bytes=entry['source'][1], sha256=entry['source'][2]) and
         delta['candidate'] == dict(path=entry['candidate'][0], bytes=entry['candidate'][1],
                                    sha256=entry['candidate'][2]), 'cache_actual_seed_delta_bindings')
    partial = [dict(row, name='profile_cache_seed') for row in delta['replacements']]
    old_method, new_method = profile_method(before).encode('ascii'), profile_method(seed).encode('ascii')
    need(len(partial) == 7 and all(row['count'] == 1 for row in partial) and
         replay(old_method, partial) == new_method and replay(new_method, partial, True) == old_method,
         'cache_actual_partial_seed_inverse')
    old_node, new_node = (ast.parse(raw.decode('ascii'), feature_version=(3, 5)).body[0]
                          for raw in (old_method, new_method))
    need(ast.dump(old_node, include_attributes=False) ==
         ast.dump(remove_cache_assignments(new_node), include_attributes=False),
         'cache_only_original_last_data_no_other_calls_or_control')
    need(delta['schema'] == 'p011-receive-profile-cache-v1-exactsource-delta' and
         delta['business_delta_count'] == 1 and delta['business_methods'] == ['_live_profile'] and
         delta['cache_labels'] == ['python', 'proc', 'daemon', 'namespace', 'endpoint', 'continuity'] and
         delta['cache_field'] == 'profile_cache' and delta['cache_append_count'] == 6 and
         delta['byte_delta'] == entry['byte_delta'] and delta['additional_clock_calls'] == 0 and
         delta['additional_io_calls'] == 0 and delta['deadlines_changed'] is False and
         delta['permission_cache_created'] is False and delta['device_executed'] is False and
         delta['rf_executed'] is False, 'cache_seed_exact_data_scope')
    need(jraw(delta) == inputs[entry['seed_delta'][0]], 'cache_canonical_seed_delta')



def validate_prepare20_business(inputs, entry):
    """One authorized equal-length constant inverse; all method guards exact."""
    before, seed = inputs[entry['source'][0]], inputs[entry['candidate'][0]]
    need((len(before), digest(before)) == tuple(entry['source'][1:]) and
         (len(seed), digest(seed)) == tuple(entry['candidate'][1:]), 'prepare20_business_pins')
    edits = [dict(name='startup_read_seconds_only', before='STARTUP_READ_SECONDS = 10.0\n',
                  after='STARTUP_READ_SECONDS = 20.0\n', count=1)]
    need(entry['edits'] == edits and replay(before, edits) == seed and
         replay(seed, edits, True) == before and len(before) == len(seed) and
         entry['byte_delta'] == 0, 'prepare20_single_constant_complete_byte_inverse')
    need(definition_rows(before) == definition_rows(seed), 'prepare20_all_definition_bytes_exact')
    def methods(raw):
        return tuple(ast.dump(node, include_attributes=True)
            for node in ast.walk(ast.parse(raw.decode('ascii'), feature_version=(3, 5)))
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)))
    need(methods(before) == methods(seed) and
         literal_assignment(before, 'STARTUP_READ_SECONDS') == 10.0 and
         literal_assignment(seed, 'STARTUP_READ_SECONDS') == 20.0 and
         ast.dump(ast.parse(replay(seed, edits, True)), include_attributes=True) ==
         ast.dump(ast.parse(before), include_attributes=True), 'prepare20_method_positions_and_ast_inverse')
    delta = json.loads(inputs[entry['seed_delta'][0]].decode('ascii'))
    need(delta == entry['seed_delta_expected'] and jraw(delta) == inputs[entry['seed_delta'][0]] and
         delta['origin'] == dict(path=entry['source'][0], bytes=entry['source'][1], sha256=entry['source'][2]) and
         delta['candidate'] == dict(path=entry['candidate'][0], bytes=entry['candidate'][1],
                                    sha256=entry['candidate'][2]), 'prepare20_actual_seed_delta')
    need(delta['schema'] == 'p011-receive-startup-20s-v1-exactsource-delta' and
         delta['replacements'] == [dict(before=edits[0]['before'], after=edits[0]['after'], count=1)] and
         delta['business_constants'] == ['STARTUP_READ_SECONDS'] and delta['business_methods'] == [] and
         delta['business_delta_count'] == 1 and delta['byte_delta'] == 0 and
         delta['all_class_function_bytes_unchanged'] is True and
         delta['all_class_function_position_ast_unchanged'] is True and
         delta['original_10s_sources_and_history_unchanged'] is True and
         delta['outer_60_plus_60_caps_changed'] is False and delta['alarm240_changed'] is False and
         delta['host250_changed'] is False and delta['stage_close_caps_changed'] is False and
         delta['profile_cache_changed'] is False and delta['proc_dispatch_candidate_integrated'] is False and
         delta['automatic_phone_window_requested'] is False, 'prepare20_exact_authorized_scope')

def validate_manifest_inverse(inputs, entries):
    for entry in entries:
        old = json.loads(inputs[entry['source'][0]].decode('ascii'))
        current = json.loads(inputs[entry['candidate'][0]].decode('ascii'))
        restored = copy.deepcopy(current)
        for index, before, after in entry['changes']:
            need(old['sources'][index] == before and current['sources'][index] == after,
                 'cache_manifest_exact_delta')
            restored['sources'][index] = before
        if entry['private']:
            need(current['previous_manifest_sha256'] == entry['source'][2],
                 'cache_private_manifest_current_parent')
            restored['previous_manifest_sha256'] = old['previous_manifest_sha256']
        need(restored == old and jraw(current) == inputs[entry['candidate'][0]], 'cache_manifest_inverse')


def verify_inputs(inputs):
    """New flat graph validator; old business provenance is not new cache count."""
    for path, size, sha in ORIGIN_SOURCE_PINS:
        need(path in inputs and (len(inputs[path]), digest(inputs[path])) == (size, sha), 'cache_flat_pin')
    need(inputs[OLD_MANIFEST[0]] == ORIGINAL_MANIFEST_RAW and
         inputs[OLD_PRIVATE_MANIFEST[0]] == OLD_PRIVATE_RAW, 'cache_original_manifests')
    need(json.loads(inputs[DELTA_SPEC[0]].decode('ascii')) == DELTA_EXPECTED, 'cache_exact_delta_metadata')
    # These retained pure byte-inverse checks do not call old verify/main/test.
    validate_owner_business(inputs, OWNER_BUSINESS_EXPECTED)
    validate_scope_business(inputs, SCOPE_BUSINESS_EXPECTED)
    validate_fc_http_delta(inputs, FC_HTTP_EXPECTED)
    validate_profile_business(inputs, CACHE_BUSINESS_EXPECTED)
    validate_prepare20_business(inputs, BUSINESS_EXPECTED)
    need(BUSINESS_CLOSURE_COUNT == 1, 'cache_one_new_business_closure')
    for entry in MOTHER_MECHANICAL_EXPECTED + MECHANICAL_EXPECTED:
        before, after = inputs[entry['source'][0]], inputs[entry['candidate'][0]]
        validate_delta(before, after, entry['edits'], entry['functions_unchanged'])
        need(len(before) == len(after), 'cache_equal_length_mechanical_source')
    validate_manifest_inverse(inputs, MOTHER_MANIFEST_EXPECTED + MANIFEST_EXPECTED)
    need(json.loads(inputs[MOTHER_DELTA[0]].decode('ascii')) == MOTHER_DELTA_EXPECTED and
         json.loads(inputs[MOTHER_GENERATION[0]].decode('ascii')) == MOTHER_GENERATION_EXPECTED,
         'cache_current_mother_graph_provenance')
    need(tuple(tuple(row) for row in MOTHER_GENERATION_EXPECTED['output_pins']) ==
         MOTHER_OUTPUT_PINS[:9], 'cache_exact_mother_output_inventory')
    baseline = MOTHER_ORDINARY_ROWS + HELPERS + MOTHER_PRIVATE_ROWS + (WPA, MONITOR)
    need(len(baseline) == 75 and sum(row[2] for row in baseline) == MOTHER_PAYLOAD_BYTES,
         'cache_actual_mother75_budget')
    for name, path, size, sha in baseline:
        need((len(inputs[path]), digest(inputs[path])) == (size, sha), 'cache_actual_mother75_pin')
    payload = manifest_rows(inputs[MANIFEST[0]]) + HELPERS + manifest_rows(inputs[PRIVATE_MANIFEST[0]], True) + (WPA, MONITOR)
    need(len(payload) == 75 and len(set(row[0] for row in payload)) == 75, 'cache75_unique')
    changed = []
    for row, before in zip(payload, ORIGINAL_PAYLOAD_ROWS):
        need(row[0] == before[0] and (len(inputs[row[1]]), digest(inputs[row[1]])) == row[2:], 'cache75_actual')
        if row[0] in CHANGED_PAYLOAD_ROLES:
            need(row != before, 'cache_changed_role')
            changed.append(row[0])
        else:
            need(row == before and inputs[row[1]] == inputs[before[1]], 'cache69_original_roles')
    need(tuple(changed) == CHANGED_PAYLOAD_ROLES and sum(row[2] for row in payload) == PAYLOAD_BYTES and
         PAYLOAD_BYTES == MOTHER_PAYLOAD_BYTES + BUSINESS_EXPECTED['byte_delta'] <= PAYLOAD_CAP == 4194304,
         'cache6_changed_payload_budget')
    validate_runner(inputs[RUNNER[0]], ORDINARY_ROWS, PRIVATE_ROWS, HELPERS, WPA, MONITOR)
    need(FILECENTER_SOURCE_PINS == ORIGINAL_FILECENTER_ROWS and len(FILECENTER_SOURCE_PINS) == 9 and
         sum(row[2] for row in FILECENTER_SOURCE_PINS) == FILECENTER_BYTES == 113832 <= 131072,
         'cache_separate_fc9_exact_budget')
    for name, path, size, sha in FILECENTER_SOURCE_PINS:
        need((len(inputs[path]), digest(inputs[path])) == (size, sha), 'cache_all_fc9_original_pins')
    owner_row = next(row for row in ORDINARY_ROWS if row[0] == 'mta_client_service_owner')
    old_owner = next(row for row in MOTHER_ORDINARY_ROWS if row[0] == 'mta_client_service_owner')
    expected_pins = tuple((name, size, sha) for name, path, size, sha in FILECENTER_SOURCE_PINS)
    need(literal_assignment(inputs[owner_row[1]], 'FILECENTER_PINS') == expected_pins and
         owner_context(inputs[owner_row[1]]) == owner_context(inputs[old_owner[1]]),
         'cache_actual_owner_fc9_and_context')
    factory = next(row for row in ORDINARY_ROWS if row[0] == 'mta_client_receive_factory')
    need(profile_method(inputs[factory[1]]) == profile_method(inputs[BUSINESS_EXPECTED['candidate'][0]]),
         'cache_actual_factory_business_seed_binding')
    need(literal_assignment(inputs[factory[1]], 'STARTUP_READ_SECONDS') == 20.0 and
         profile_method(inputs[factory[1]]) == profile_method(inputs[MOTHER_OUTPUT_PINS[3][0]]),
         'prepare20_actual_constant_and_original_profile')
    need(json.loads(inputs[GENERATION[0]].decode('ascii')) == GENERATION_EXPECTED, 'cache_generation_exact')
    return MECHANICAL_CLOSURE_COUNT


def prepare():
    """Pure read/derive with current mother outputs, never old execution."""
    need(len(ROOT_BEFORE) == len(ROOT_AFTER), 'equal_length_isolated_root')
    need(all(type(row) is tuple and len(row) == 3 for row in (PREPARE_SEED, PREPARE_DELTA, PREPARE_GENERATOR)),
         'prepare20_seed_final_pins_required')
    inputs = {MOTHER[0]: read_pin(MOTHER), GENERATOR_MOTHER[0]: read_pin(GENERATOR_MOTHER),
              MECHANICAL_HELPERS[0]: read_pin(MECHANICAL_HELPERS)}
    mother = inputs[MOTHER[0]]
    origin_rows = literal_assignment(mother, 'ORIGIN_SOURCE_PINS')
    need(type(origin_rows) is tuple and len(origin_rows) == 289, 'actual_cache_flat289')
    for row in origin_rows + MOTHER_OUTPUT_PINS + (PREPARE_SEED, PREPARE_DELTA, PREPARE_GENERATOR):
        raw = read_pin(row)
        need(row[0] not in inputs or inputs[row[0]] == raw, 'flat_duplicate_identity')
        inputs[row[0]] = raw
    inputs[SELF] = scoped(SELF).read_bytes()
    helpers = pure_helpers(inputs[MECHANICAL_HELPERS[0]])
    # Bind only the seven selected helper definitions for this pure preparation.
    replay, validate_delta = helpers.replay, helpers.validate_delta
    assignment, source_tuple = helpers.assignment, helpers.source_tuple
    values = {name: literal_assignment(mother, name) for name in INTERFACE_CONSTANTS}
    old_manifest, old_private, old_runner = (literal_assignment(mother, name) for name in ('MANIFEST', 'PRIVATE_MANIFEST', 'RUNNER'))
    ordinary, private = (json.loads(inputs[row[0]].decode('ascii')) for row in (old_manifest, old_private))
    need(jraw(ordinary) == inputs[old_manifest[0]] and jraw(private) == inputs[old_private[0]], 'mother_manifest_canonical')
    old_rows = {row['module']: (row['path'], row['bytes'], row['sha256']) for row in ordinary['sources']}
    private_rows_old = tuple(('runtime35/' + row['module'], row['path'], row['bytes'], row['sha256']) for row in private['sources'])
    original_payload = tuple((row['module'], row['path'], row['bytes'], row['sha256']) for row in ordinary['sources']) + values['HELPERS'] + private_rows_old + (values['WPA'], values['MONITOR'])
    need(len(old_rows) == 35 and len(private_rows_old) == 35 and len(original_payload) == 75 and
         sum(row[2] for row in original_payload) == MOTHER_PAYLOAD_BYTES and
         literal_assignment(mother, 'ROOT_AFTER') == ROOT_BEFORE and
         literal_assignment(mother, 'PAYLOAD_BYTES') == MOTHER_PAYLOAD_BYTES and
         original_payload == literal_assignment(mother, 'ORDINARY_ROWS') + values['HELPERS'] +
             literal_assignment(mother, 'PRIVATE_ROWS') + (values['WPA'], values['MONITOR']), 'actual_current75_fccap')
    mother_delta, mother_generation = (literal_assignment(mother, name) for name in ('DELTA_SPEC', 'GENERATION'))
    mother_delta_value, mother_report = (json.loads(inputs[row[0]].decode('ascii')) for row in (mother_delta, mother_generation))
    need(mother_delta_value == literal_assignment(mother, 'DELTA_EXPECTED') and
         mother_report == literal_assignment(mother, 'GENERATION_EXPECTED') and
         tuple(tuple(row) for row in mother_report['output_pins']) == MOTHER_OUTPUT_PINS[:9] and
         mother_report['generator'] == list(GENERATOR_MOTHER), 'actual_current_mother_output_closure')
    fc_rows = values['FILECENTER_SOURCES']
    need(len(fc_rows) == 9 and sum(row[2] for row in fc_rows) == FILECENTER_BYTES <= FILECENTER_CAP,
         'actual_fc9_unchanged_budget')
    need(PREPARE_SEED[0].endswith('/runtime/mta_client_receive_factory.py') and
         old_rows['mta_client_receive_factory'] == MOTHER_OUTPUT_PINS[3], 'actual_current_factory_source')
    seed_delta = json.loads(inputs[PREPARE_DELTA[0]].decode('ascii'))
    delta_bytes = len(inputs[PREPARE_SEED[0]]) - len(inputs[old_rows['mta_client_receive_factory'][0]])
    business = dict(source=list(old_rows['mta_client_receive_factory']), candidate=list(PREPARE_SEED),
        seed_delta=list(PREPARE_DELTA), seed_generator=list(PREPARE_GENERATOR), seed_delta_expected=seed_delta,
        byte_delta=delta_bytes, edits=[dict(name='startup_read_seconds_only',
            before='STARTUP_READ_SECONDS = 10.0\n', after='STARTUP_READ_SECONDS = 20.0\n', count=1)])
    # The validator uses only pure helper names, never a loaded target module.
    validator = types.ModuleType('fixed_receive_profile_cache_business_inverse')
    validator.__dict__.update(ast=ast, json=json, need=need, digest=digest, jraw=jraw,
                             replay=replay, definition_rows=helpers.definition_rows,
                             profile_method=profile_method, CACHE_BYTE_CAP=CACHE_BYTE_CAP)
    validator.__dict__['literal_assignment'] = literal_assignment
    validation_source = source_function(inputs[SELF], 'validate_prepare20_business')
    exec(compile(validation_source, '<fixed-prepare20-constant-inverse>', 'exec'), validator.__dict__)
    validator.validate_prepare20_business(inputs, business)
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
    create('mta_client_receive_factory', PREPARE_SEED, [root('ASSET_ROOT'),
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
             after="        physical = '/var/volatile/tmp/" + ROOT_AFTER + "'\n", count=1)])
    owner = new_pins['mta_client_service_owner']
    need(helpers.owner_context(outputs[owner[0]]) == helpers.owner_context(inputs[old_rows['mta_client_service_owner'][0]]) and
         literal_assignment(outputs[owner[0]], 'FILECENTER_PINS') ==
         tuple((name, size, sha) for name, path, size, sha in fc_rows), 'actual_owner_context_fc9_unchanged')
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
         changed == CHANGED_PAYLOAD_ROLES and total == MOTHER_PAYLOAD_BYTES + delta_bytes <= PAYLOAD_CAP and
         len(mechanical) == 6, 'actual_six_mechanical_75_budget')
    for row, before in zip(payload, original_payload):
        if row[0] not in CHANGED_PAYLOAD_ROLES:
            need(row == before and inputs[row[1]] == inputs[before[1]], 'actual69_original_payload_bytes')
    helpers.validate_runner(outputs[core[0]], rows, private_rows, values['HELPERS'], values['WPA'], values['MONITOR'])
    need(literal_assignment(outputs[executor[0]], 'MODULES') == values['PRIVATE_MODULE_NAMES'], 'executor35_order')
    boot_raw, factory_raw = outputs[new_pins['mta_client_receive_boot'][0]], outputs[new_pins['mta_client_receive_factory'][0]]
    need(literal_assignment(boot_raw, 'F37_SHA') == executor[2] and
         ("    ('mta_client_executor', " + str(executor[1]) + ', F37_SHA),\n').encode('ascii') in boot_raw and
         ("SOURCE_PINS[0] != ('mta_client_executor', " + str(executor[1]) + ', F37_SHA)').encode('ascii') in boot_raw and
         literal_assignment(factory_raw, 'F_SHA') == executor[2] and
         factory_raw.count(("    ('mta_client_executor', " + str(executor[1]) + ', F_SHA),\n').encode('ascii')) == 1 and
         profile_method(factory_raw) == profile_method(inputs[PREPARE_SEED[0]]), 'actual_boot_factory_executor_cache_binding')
    manifests = [dict(source=list(old_manifest), candidate=list(manifest_pin), private=False, changes=changes),
        dict(source=list(old_private), candidate=list(private_pin), private=True,
             changes=[[private_index, private['sources'][private_index], private_new['sources'][private_index]]])]
    spec = dict(schema='p011-receive-startup-20s-v1-graph-delta', root=ROOT_AFTER,
        mother=list(MOTHER), mechanical=mechanical, business=business, manifests=manifests,
        new_business_closure_count=1, changed_roles=list(changed), payload_bytes=total,
        payload_cap=PAYLOAD_CAP, unchanged_payload_roles=69, private_roles_exact=34,
        filecenter_bytes=FILECENTER_BYTES, filecenter_cap=FILECENTER_CAP, filecenter_exact_roles=9,
        filecenter_sources_changed=False, inherited_owner_scope_fc_http_provenance_preserved=True,
        proc_native_wpa_monitor_unchanged=True, state_protocol_unchanged=True,
        measured_owner_context_preserved=True, native_authority_changed=False,
        outer_deadlines_preserved=True, startup_prepare_seconds_before=10.0, startup_prepare_seconds_after=20.0,
        independent_candidate_only=True, original_10s_sources_and_history_unchanged=True,
        proc_dispatch_candidate_integrated=False, automatic_phone_window_requested=False, cache_data_not_authority=True,
        rf_requested=False, send_graph_changed=False)
    outputs[SPEC_PATH] = jraw(spec)
    need(len(outputs[SPEC_PATH]) <= 131072, 'finite_graph_delta_metadata')
    delta_pin = pin(SPEC_PATH, outputs[SPEC_PATH])
    origin = {path: pin(path, raw) for path, raw in inputs.items()}
    need(not set(origin).intersection(outputs), 'immutable_output_partition')
    origin.update((path, pin(path, raw)) for path, raw in outputs.items())
    report = dict(schema='p011-receive-startup-20s-v1-graph-generation',
        status='SOURCE_DERIVED_NOT_DEVICE_TESTED', generator=list(pin(SELF, inputs[SELF])),
        mother=list(MOTHER), generator_mother=list(GENERATOR_MOTHER), source_origin_count=len(origin) + 1,
        mechanical_closure_count=6, new_business_closure_count=1, new_business_methods=[],
        new_business_constants=['STARTUP_READ_SECONDS'],
        business_byte_delta=delta_bytes, business_byte_cap=0,
        inherited_owner_scope_fc_http_provenance_preserved=True,
        changed_payload_roles=list(changed), exact_payload_roles=69, private_roles_exact=34,
        payload_bytes=total, payload_cap=PAYLOAD_CAP, payload_remaining=PAYLOAD_CAP - total,
        filecenter_bytes=FILECENTER_BYTES, filecenter_remaining=FILECENTER_CAP - FILECENTER_BYTES,
        filecenter_sources=9, filecenter_exact_roles=9, filecenter_sources_changed=False,
        root=ROOT_AFTER, headless_only=True, navigation_ui_outputs=False,
        measured_owner_context_preserved=True, state_protocol_proc_native_wpa_monitor_unchanged=True,
        outer_deadlines_preserved=True, startup_prepare_seconds_before=10.0, startup_prepare_seconds_after=20.0,
        independent_candidate_only=True, original_10s_sources_and_history_unchanged=True,
        proc_dispatch_candidate_integrated=False, automatic_phone_window_requested=False, cache_data_not_authority=True,
        output_pins=[list(pin(path, raw)) for path, raw in sorted(outputs.items())], definitions_path=DEFINITIONS,
        definitions_and_report_pins_omitted_to_avoid_cycles=True, old_main_build_verify_called=False,
        old_tests_replayed=0, device_tested=False, phone_tested=False, rf_requested=False,
        new_device_root_checked=False, send_graph_changed=False, profile_cache_performance_verified=False)
    outputs[REPORT_PATH] = jraw(report)
    report_pin = pin(REPORT_PATH, outputs[REPORT_PATH])
    origin[REPORT_PATH] = report_pin
    source_pins = tuple(origin[path] for path in sorted(origin))
    constants = dict(MOTHER=MOTHER, GENERATOR_MOTHER=GENERATOR_MOTHER, MECHANICAL_HELPERS=MECHANICAL_HELPERS,
        MOTHER_OUTPUT_PINS=MOTHER_OUTPUT_PINS, PREPARE_SEED=PREPARE_SEED, PREPARE_DELTA=PREPARE_DELTA,
        PREPARE_GENERATOR=PREPARE_GENERATOR, CACHE_BYTE_CAP=CACHE_BYTE_CAP,
        MANIFEST=manifest_pin, PRIVATE_MANIFEST=private_pin, RUNNER=core, EXECUTOR_PIN=executor,
        OLD_MANIFEST=old_manifest, ORIGINAL_MANIFEST=old_manifest, OLD_PRIVATE_MANIFEST=old_private,
        DELTA_SPEC=delta_pin, GENERATION=report_pin, ROOT_BEFORE=ROOT_BEFORE, ROOT_AFTER=ROOT_AFTER,
        STATE_ROOT='/var/volatile/tmp/' + ROOT_AFTER, STATE_ALIAS='/tmp/' + ROOT_AFTER, RUNTIME_PREFIX=RUNTIME,
        CHANGED=CHANGED, PRIVATE_CHANGED=('mta_client_executor',), CHANGED_PAYLOAD_ROLES=CHANGED_PAYLOAD_ROLES,
        MECHANICAL_CLOSURE_COUNT=6, BUSINESS_CLOSURE_COUNT=1,
        FC_CHANGED=literal_assignment(mother, 'FC_CHANGED'),
        PAYLOAD_BYTES=total, PAYLOAD_CAP=PAYLOAD_CAP, MOTHER_PAYLOAD_BYTES=MOTHER_PAYLOAD_BYTES,
        FILECENTER_BYTES=FILECENTER_BYTES, FILECENTER_CAP=FILECENTER_CAP,
        ORIGIN_SOURCE_PINS=source_pins, ORIGINAL_PAYLOAD_ROWS=original_payload,
        ORIGINAL_FILECENTER_ROWS=fc_rows, ORDINARY_ROWS=rows, PRIVATE_ROWS=private_rows,
        MECHANICAL_EXPECTED=mechanical, BUSINESS_EXPECTED=business,
        CACHE_BUSINESS_EXPECTED=literal_assignment(mother, 'BUSINESS_EXPECTED'),
        SCOPE_BUSINESS_EXPECTED=literal_assignment(mother, 'SCOPE_BUSINESS_EXPECTED'),
        OWNER_BUSINESS_EXPECTED=literal_assignment(mother, 'OWNER_BUSINESS_EXPECTED'),
        FC_HTTP_EXPECTED=literal_assignment(mother, 'FC_HTTP_EXPECTED'),
        MOTHER_MECHANICAL_EXPECTED=literal_assignment(mother, 'MOTHER_MECHANICAL_EXPECTED') +
            literal_assignment(mother, 'MECHANICAL_EXPECTED'),
        MOTHER_MANIFEST_EXPECTED=literal_assignment(mother, 'MOTHER_MANIFEST_EXPECTED') +
            literal_assignment(mother, 'MANIFEST_EXPECTED'),
        MOTHER_DELTA=mother_delta, MOTHER_DELTA_EXPECTED=mother_delta_value,
        MOTHER_GENERATION=mother_generation, MOTHER_GENERATION_EXPECTED=mother_report,
        MOTHER_ORDINARY_ROWS=literal_assignment(mother, 'ORDINARY_ROWS'),
        MOTHER_PRIVATE_ROWS=literal_assignment(mother, 'PRIVATE_ROWS'),
        MANIFEST_EXPECTED=manifests, DELTA_EXPECTED=spec, GENERATION_EXPECTED=report,
        ORIGINAL_MANIFEST_RAW=inputs[old_manifest[0]], OLD_PRIVATE_RAW=inputs[old_private[0]], **values)
    header = '\n'.join(('"""Independent authorized prepare20 graph; original10 history unchanged, no device acceptance."""',
        'import ast', 'import copy', 'import hashlib', 'import json', 'import os', 'from pathlib import Path',
        'import re', 'import stat', 'import types', '', 'BASE = Path(__file__).resolve().parents[1]') +
        tuple(name + ' = ' + repr(value) for name, value in constants.items()))
    reusable = '\n\n'.join(source_function(mother, name) for name in REUSED_FUNCTIONS)
    own_functions = '\n\n'.join(source_function(inputs[SELF], name) for name in (
        'profile_method', 'validate_profile_business', 'validate_prepare20_business',
        'validate_manifest_inverse', 'verify_inputs'))
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
    """EXCL or exact existing bytes; preflight all before any publication."""
    need(type(outputs) is dict and len(outputs) == 11, 'eleven_outputs_required')
    destinations = {}
    for path, raw in outputs.items():
        need(type(raw) is bytes and (path.startswith(PREFIX) or
             path in (DEFINITIONS, MANIFEST_PATH, PRIVATE_MANIFEST_PATH)) and path != SELF,
             'output_namespace')
        target = scoped(path)
        if target.exists():
            need(stat.S_ISREG(target.lstat().st_mode) and target.read_bytes() == raw,
                 'existing_output_incompatible:' + path)
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

