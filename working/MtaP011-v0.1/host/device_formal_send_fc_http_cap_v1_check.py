"""SOURCE-only actual sender HTTP-cap UI/carrier linkage; no device mode.

One independently versioned parent derives the measured status sender's final
HOST bytes. Its 17 fields, smoke20, UI600+cleanup60, carrier800/HOST810, raw
receipts, guardian restore and finally predicates are retained in the derived
source. Only pure preparation and byte generation are called on this PC.
Stage/CONTROL/DEVICE options explicitly fail: the new ordinary root has not
been staged by this entry. No original/derived main, runtime method, generator,
test, ADB, Qt, RF, phone, credentials or GUI publication is executed.
"""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import sys
import traceback
import types
import uuid

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_fc_http_cap_v1_check.py'
CMD = 'HOST_MTA_FORMAL_SEND_FC_HTTP_CAP_V1_SOURCE_CHECK.cmd'
ROOT = 'candidate/formal-send-fc-http-cap-v1'
REMOTE_ROOT = '/tmp/p011-mta-formal-send-filecenter-httpcp-v1'
PHYSICAL_ROOT = '/var/volatile/tmp/p011-mta-formal-send-filecenter-httpcp-v1'
SESSION = '6d4fb1fd4af949cbb3515870'
BUNDLE = 'out/mta-ui-send-status-v1-' + SESSION
CONTROL_SUFFIX = '-formal-send-fc-http-cap-v1'
MOTHER = ('host/device_formal_send_status_ui_v1_check.py', 10897,
          '2cffbaa0f86bcf4f5e73b2c1fbc7dcf16c91f731da311d66db57f1e7f5bb024a')
PREPARE_PINS = (
    MOTHER,
    ('host/device_formal_send_preflight_ui_v1_check.py', 19048,
     'fcbf17242702204af54476798dffcc402f748b32a8f05a50933df695a3e9120e'),
    ('host/device_formal_send_repair_ui_v1_check.py', 13163,
     '3efc100b3a91fa5b6cdf9dc3f51a9c545d3fbc1a885d0c3ab288823997dc390c'),
    ('host/device_formal_send_filecenter_ui_v7_check.py', 28635,
     'b888055f21b21eb60d003e8dd00fde62646ef1dd2628d568146b987689ed2449'),
    ('host/device_formal_send_status_ui_assets_v1_check.py', 15921,
     '7f1d9a506c980f64daaea8f6bb327301c5f4626d4592b45de8a1d59abc002ee8'),
)
READER = ('host/filecenter_http_cap_package_v1_check.py', 18182,
          '0d0b7382b930d02de4845679b9aabde571c9ea3593175d8e9af07f48299dda7d')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
GENERATION = (ROOT + '/generation.json', 27597,
              'a2bdae7d8e32c90e8f8926388fd1156c5c3169d1a41b0220f12895324ea33fb1')
PACKAGE_PINS = (
    (ROOT + '/assets/filecenter-source-manifest.json', 2476,
     '819879157ba075d1afeb5bfad88e911408f5b060402166199c67b4b654a1d8a5'),
    (ROOT + '/assets/ordinary-source-manifest.json', 20762,
     '6a478fc8bc8a61db8d43d1e89d10d1363c76fc3762fa51500dbe95539d794802'),
    (ROOT + '/exactsource-delta.json', 21983,
     'e460ecea60411ce742d350f4f8a527ee7d425ced6f5a077f2843dce16d0abe07'),
    (ROOT + '/runtime/formal_send_session.py', 24060,
     '893b7d154ddc21ddd3120c356093f42fdd373e8df5101094535e00194ad10231'),
    (ROOT + '/runtime/formal_send_stage.py', 37421,
     '50e5fcf4d439733c79f69f5665c1bc10efaebc5bbfc570f745bf619212d5e369'),
    (ROOT + '/runtime/mta_client_receive_boot.py', 19583,
     '4051ebd41ca18a8dc7485411a62ae8c9ed0dcf60aeacb4f26f5d59b9f03205d1'),
    (ROOT + '/runtime/mta_client_service_owner.py', 103959,
     '5ff1afa7a262fe4a427ea6b8a99fe208da177a3d719f75f5fe7299277ea81592'),
    (ROOT + '/runtime/mta_send_terminal_consumer.py', 12785,
     'e7e440158b93f5e76994803bb9810dc2339d90086afd9ab0268f30c022c5f674'),
    (ROOT + '/runtime/mta_send_trial.py', 22052,
     'f5548048a5cfcca85d96a49c181213521e6b0521c8575c8a31440527e5e1d865'),
    (ROOT + '/runtime/mta_service.py', 145733,
     '2b1ec27d4b0949d67d9da8f408d17e68aaa0c32b78e6e8e1ba6924108b924c9b'),
    (ROOT + '/runtime/ui_assets.py', 12526,
     '430308223593d5d783c1ec1d29a90dcbe82606b33690fc263572b8353d9fd4e8'),
    (ROOT + '/runtime/ui_guardian.py', 43991,
     '0eb853e9db532bc1bb28079da4170987e29d1ccb361b23c16e878b39a0199ad0'),
    (ROOT + '/runtime/ui_session.py', 46414,
     '7be5f60455b89b99d23ad25a8d1cb5055bacf7511755ffeac461fad3fffd1bb8'),
    GENERATION,
)
FC_MANIFEST, CATALOG, DELTA, OUTER, STAGE, BOOT, OWNER = PACKAGE_PINS[:7]
VALIDATOR, GUARDIAN, WORKER = PACKAGE_PINS[10:13]
SOURCE_BASELINES = PREPARE_PINS + PACKAGE_PINS
PREPARE_NAMES = frozenset(('need', 'digest', 'tree', 'assignment', 'span',
    'pure_definitions', 'source_boundary', 'derive_host', 'prepare'))
READER_NAMES = frozenset(('need', 'sha', 'metadata', 'read_fixed'))
UI_BOOLS = ('complete', 'ui_ready', 'credentials_removed', 'original_ui_exited', 'candidate_exited',
    'owner_closed', 'guardian_exited', 'stock_restored', 'worker_fds_closed', 'resource_pending',
    'automatic_rf_action', 'receive_worker_started', 'filecenter_parent_deadline_verified',
    'filecenter_parent_deadline_wired', 'smoke_requested')
UI_FIELDS = frozenset(UI_BOOLS + ('automatic_stop_seconds', 'reason'))
DISCONNECTED_OPTIONS = ('--check-device', '--stage-device', '--control-device')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def tree(raw):
    return ast.parse(raw.decode('utf-8'))


def assignment(raw, name):
    nodes = [node for node in tree(raw).body if isinstance(node, ast.Assign) and
             len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(nodes) == 1, 'unique_assignment')
    return nodes[0]


def literal(raw, name):
    return ast.literal_eval(assignment(raw, name).value)


def span(raw, node):
    return b''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def pure_module(raw, path, name, names=None):
    """Fixed imports/constants and an exact pure function set; no old main."""
    parsed = tree(raw)
    selected = [node for node in parsed.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign)) or
                isinstance(node, ast.FunctionDef) and (names is None and node.name != 'main' or
                                                      names is not None and node.name in names)]
    chosen = {node.name for node in selected if isinstance(node, ast.FunctionDef)}
    need('main' not in chosen and (names is None or chosen == names), 'pure_inventory')
    value = types.ModuleType(name)
    value.__file__ = str(BASE / path)
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<' + name + '>', 'exec'), value.__dict__)
    need('main' not in value.__dict__, 'old_main_excluded')
    return value


def reader_module():
    # Authenticate the fixed safe reader before executing its four pure helpers.
    raw = (BASE / READER[0]).read_bytes()
    need((len(raw), digest(raw)) == READER[1:], 'reader_pin')
    return pure_module(raw, READER[0], '_send_http_cap_v1_reader', READER_NAMES)


def retain(reader, inputs, pin, evidence=None):
    raw = reader.read_fixed(pin[0])
    if evidence is not None:
        evidence._retain(pin[0], raw)
    else:
        need(pin[0] not in inputs or inputs[pin[0]] == raw, 'source_changed')
        inputs[pin[0]] = raw
    need((len(raw), digest(raw)) == tuple(pin[1:]), 'source_pin')
    return raw


def reverse_record(inputs, row):
    source, candidate = tuple(row['source']), tuple(row['candidate'])
    old, new = inputs[source[0]], inputs[candidate[0]]
    need((len(old), digest(old)) == source[1:] and (len(new), digest(new)) == candidate[1:], 'delta_pins')
    if row.get('identical_bytes') is True:
        need(old == new, 'identical_mirror')
        return
    forward, inverse = old, new
    steps = row['substitutions']
    need(type(steps) is list and 1 <= len(steps) <= 16, 'finite_delta')
    for item in steps:
        before, after = item['before'].encode('utf-8'), item['after'].encode('utf-8')
        count = item['count']
        need(before and after and before != after and type(count) is int and 1 <= count <= 100 and
             forward.count(before) == count, 'forward_anchor')
        forward = forward.replace(before, after, count)
    for item in reversed(steps):
        before, after = item['before'].encode('utf-8'), item['after'].encode('utf-8')
        need(inverse.count(after) == item['count'], 'inverse_anchor')
        inverse = inverse.replace(after, before, item['count'])
    need(forward == new and inverse == old, 'complete_byte_inverse')
    if candidate[0].endswith('.py'):
        need(ast.dump(tree(inverse), include_attributes=True) == ast.dump(tree(old), include_attributes=True),
             'complete_ast_inverse')


def package_boundary(reader, inputs, evidence=None):
    """Actual 14-output send package, not an old 27-output GUI/Owner boundary."""
    for row in PACKAGE_PINS:
        retain(reader, inputs, row, evidence)
    facts, delta = (json.loads(inputs[row[0]]) for row in (GENERATION, DELTA))
    need(facts['schema'] == 'p011-formal-send-fc-http-cap-v1-generation' and
         facts['scope'] == 'PC_SOURCE_ONLY_NOT_STAGED_NOT_RUN' and facts['output_count'] == 14 and
         facts['output_pins'] == [list(row) for row in sorted(PACKAGE_PINS[:-1])] and
         tuple(facts['worker']) == WORKER and tuple(facts['guardian']) == GUARDIAN and
         tuple(facts['assets_validator']) == VALIDATOR and tuple(facts['sender_outer']) == OUTER and
         tuple(facts['ordinary_manifest']) == CATALOG and tuple(facts['filecenter_manifest']) == FC_MANIFEST and
         tuple(facts['exactsource_delta']) == DELTA and facts['ordinary_root'] == REMOTE_ROOT and
         facts['physical_ordinary_root'] == PHYSICAL_ROOT and facts['reused_gui_session'] == SESSION and
         facts['reused_gui_bundle'] == BUNDLE and facts['reused_gui_files'] == 19 and facts['reused_gui_bytes'] == 4185296,
         'actual_package_metadata')
    need(facts['filecenter_source_count'] == 9 and facts['filecenter_source_bytes'] == 100114 and
         facts['filecenter_source_cap'] == 131072 and facts['ordinary_source_count'] == 32 and
         facts['ordinary_source_bytes'] == 1078691 and facts['ordinary_batch_files'] == 37 and
         facts['ordinary_batch_bytes'] == 1368142 and facts['original_ui_window_seconds'] == 600 and
         facts['original_cleanup_seconds'] == 60 and facts['original_boot_load_seconds'] == 10 and
         facts['original_stage_seconds'] == 120 and facts['original_wire_cap_bytes'] == 4194304 and
         all(facts[key] is False for key in ('device', 'staged', 'runtime', 'host', 'native', 'rf', 'phone',
             'host_entry_connected', 'filecenter_parent_deadline_verified', 'whole_owner_closure_verified',
             'restore_verified', 'real_mobile_transfer_verified')), 'package_scope_caps')
    rows = tuple(tuple(row) for row in facts['inputs'])
    need(len(rows) == facts['input_count'] and len({row[0] for row in rows}) == len(rows) and
         tuple(facts['source_owner']) == ('candidate/formal-send-filecenter-deploy-v7/runtime/mta_client_service_owner.py',
             103959, 'b73f30f0899efc96f363b7889ff79a5c92d48fd28c73796423bdcb40230e7761') and
         tuple(facts['source_worker']) == ('candidate/formal-send-status-package-v3/runtime/ui_session.py',
             46416, 'adc1561cd32d53257c5df123c4516c63e38198a7c08a04be0fc51249d2893c25'), 'actual_v7_origins')
    for row in rows:
        retain(reader, inputs, row, evidence)
    need(delta['schema'] == 'p011-formal-send-fc-http-cap-v1-exactsource-delta' and
         delta['historical_v3_owner_not_loaded'] is True and len(delta['source_records']) == 12 and
         {tuple(row['candidate']) for row in delta['source_records']} ==
         set(PACKAGE_PINS[:-1]) - {DELTA}, 'delta_inventory')
    for row in delta['source_records']:
        reverse_record(inputs, row)
    fc, catalog = (json.loads(inputs[row[0]]) for row in (FC_MANIFEST, CATALOG))
    pins = tuple((row['module'], row['bytes'], row['sha256']) for row in fc['sources'])
    need(fc['source_count'] == len(pins) == 9 and fc['source_bytes'] == sum(row[1] for row in pins) == 100114 and
         fc['source_cap'] == 131072 and fc['in_protocol_stage_payload'] is False and
         literal(inputs[OWNER[0]], 'FILECENTER_PINS') == literal(inputs[WORKER[0]], 'FILECENTER_PINS') == pins,
         'fc9_actual_closure')
    for row in fc['sources']:
        retain(reader, inputs, (row['source'], row['bytes'], row['sha256']), evidence)
    startup = {row['module']: (row['source'], row['bytes'], row['sha256']) for row in catalog['startup_sources']}
    need(startup == {'mta_client_receive_boot': BOOT, 'mta_client_service_owner': OWNER, 'formal_send_session': OUTER} and
         catalog['ordinary_root'] == REMOTE_ROOT + '/runtime' and catalog['physical_ordinary_root'] == PHYSICAL_ROOT + '/runtime' and
         tuple(catalog['filecenter_source_manifest'].values()) == FC_MANIFEST and
         literal(inputs[OUTER[0]], 'BOOT_PIN') == literal(inputs[OWNER[0]], 'BOOT_PIN') == BOOT[1:] and
         literal(inputs[OUTER[0]], 'OWNER_PIN') == OWNER[1:] and
         literal(inputs[WORKER[0]], 'SENDER_PIN') == OUTER[1:] and
         literal(inputs[WORKER[0]], 'GUARDIAN_PIN') == GUARDIAN[1:] and
         literal(inputs[WORKER[0]], 'ASSETS_PIN') == VALIDATOR[1:] and
         literal(inputs[WORKER[0]], 'SENDER_ROOT') == literal(inputs[OUTER[0]], 'ROOT') == REMOTE_ROOT and
         literal(inputs[WORKER[0]], 'SENDER_PHYSICAL_ROOT') == literal(inputs[OUTER[0]], 'PHYSICAL_ROOT') == PHYSICAL_ROOT,
         'ordinary_startup_worker_closure')
    ordinary = []
    for row in catalog['sources'] + catalog['startup_sources'] + catalog['helper_sources']:
        retain(reader, inputs, (row['source'], row['bytes'], row['sha256']), evidence)
        if row.get('reused_sender_asset') is not True:
            need(row['physical_target'].startswith(PHYSICAL_ROOT + '/'), 'ordinary_target_scope')
            ordinary.append((row['physical_target'][len(PHYSICAL_ROOT) + 1:], row['bytes'], row['sha256'], row['mode']))
    need(literal(inputs[BOOT[0]], 'SOURCE_PINS') == tuple((row['module'], row['bytes'], row['sha256'])
         for row in catalog['sources']) and len(ordinary) == 37 and sum(row[1] for row in ordinary) == 1368142 and
         literal(inputs[STAGE[0]], 'PROFILE_FILES')[2] == ('ordinary', PHYSICAL_ROOT, tuple(ordinary)) and
         literal(inputs[STAGE[0]], 'PROFILE_TOTALS') == (('sender', 27, 2402458), ('observer', 41, 1548495),
                                                      ('ordinary', 37, 1368142)), 'stage_inventory_source_only')
    expected_control = ast.dump(ast.parse("'p011-mta-ui-session-' + SESSION + " + repr(CONTROL_SUFFIX), mode='eval').body)
    for row in (WORKER, GUARDIAN):
        need(literal(inputs[row[0]], 'SESSION') == SESSION and
             ast.dump(assignment(inputs[row[0]], 'CONTROL_NAME').value) == expected_control, 'private_control_identity')
    ui = literal(inputs[VALIDATOR[0]], 'PINS') + (('SOURCE.sha256',) + literal(inputs[VALIDATOR[0]], 'MANIFEST_PIN'),)
    need(len(ui) == 19 and sum(row[1] for row in ui) == 4185296, 'unchanged_ui19')
    for name, size, sha in ui:
        retain(reader, inputs, (BUNDLE + '/' + name, size, sha), evidence)
    for row in PACKAGE_PINS:
        if row[0].endswith('.py'):
            ast.parse(inputs[row[0]], feature_version=(3, 5))
    return fc['sources'], dict(actual_package_outputs=14, filecenter_sources=9, filecenter_bytes=100114,
        actual_owner_v7_successor=True, full_package_byte_inverse=True, ordinary_sources=32,
        ordinary_stage_files=37, ordinary_stage_bytes=1368142, gui_files_reused=19, gui_bytes_reused=4185296,
        original_ui_results=17, private_control_source_bound=True, stage_runtime_verified=False,
        device_runtime_verified=False, full_owner_closure_verified=False)


def derive(origin):
    """Finite actual HOST identity/FC constants, with whole-byte/AST inverse."""
    raw, steps = origin, []
    def change(before, after, count=1):
        nonlocal raw
        need(type(before) is bytes and type(after) is bytes and before != after and raw.count(before) == count,
             'host_forward_anchor')
        raw = raw.replace(before, after, count)
        steps.append((before, after, count))
    replacements = dict(SELF=SELF, CMD=CMD, RUNTIME=ROOT + '/runtime/', WORKER=WORKER, GUARDIAN=GUARDIAN,
                        VALIDATOR=VALIDATOR, OUTER=OUTER, SOURCE_BASELINES=SOURCE_BASELINES)
    for name, value in replacements.items():
        change(span(raw, assignment(raw, name)), (name + ' = ' + repr(value) + '\n').encode('ascii'))
    change(b"path='candidate/formal-send-filecenter-deploy-v3/assets/filecenter-source-manifest.json'",
           ('path=' + repr(FC_MANIFEST[0])).encode('ascii'))
    change(b"(2466,'14d57b5aea7c49df0f87b6338044c86ccd155583994e83c8158c5217d7f48e1d')",
           ('(' + str(FC_MANIFEST[1]) + ',' + repr(FC_MANIFEST[2]) + ')').encode('ascii'))
    change(b'99972', b'100114', 2)
    change(b"+SESSION+'-formal-send-status-package-v3'", ("+SESSION+" + repr(CONTROL_SUFFIX)).encode('ascii'))
    change(b"for path in (SELF,CMD,CONTRACT,'HOST_MTA_FORMAL_SEND_STATUS_UI_V1_SOURCE_CHECK.cmd'):",
           ('for path in (SELF,CMD,CONTRACT,' + repr(CMD) + '):').encode('ascii'))
    change(b'fixed_sender_status_ui_v1_', b'fixed_sender_fc_http_cap_v1_', 5)
    change(b'fixed-sender-status-ui-v1-', b'fixed-sender-fc-http-cap-v1-', 1)
    change(b'formal_send_status_ui_v1_fixed_carrier_entry', b'formal_send_fc_http_cap_v1_fixed_carrier_entry')
    change(b'fixed-formal-send-status-ui-v1-bootstrap', b'fixed-formal-send-fc-http-cap-v1-bootstrap')
    change(b'fixed-status-ui-v1-carrier', b'fixed-fc-http-cap-v1-carrier')
    change(b"('formal-send-status-ui-v1-'+mode+", b"('formal-send-fc-http-cap-v1-'+mode+")
    inverse = raw
    for before, after, count in reversed(steps):
        need(inverse.count(after) == count, 'host_inverse_anchor')
        inverse = inverse.replace(after, before, count)
    need(inverse == origin and ast.dump(tree(inverse), include_attributes=True) ==
         ast.dump(tree(origin), include_attributes=True), 'host_complete_byte_ast_inverse')
    allowed = {'ui_program', 'carrier_body', 'carrier_command', 'main'}
    old_nodes, new_nodes = tree(origin).body, tree(raw).body
    changed_assignments, changed_methods = set(), set()
    need(len(old_nodes) == len(new_nodes), 'host_shape')
    for old, new in zip(old_nodes, new_nodes):
        if ast.dump(old, include_attributes=False) == ast.dump(new, include_attributes=False):
            if isinstance(old, (ast.FunctionDef, ast.ClassDef)):
                need(span(origin, old) == span(raw, new), 'other_host_definitions_byte_exact')
            continue
        if isinstance(old, ast.Assign) and isinstance(new, ast.Assign):
            need(len(old.targets) == len(new.targets) == 1 and isinstance(old.targets[0], ast.Name) and
                 ast.dump(old.targets[0]) == ast.dump(new.targets[0]) and old.targets[0].id in replacements,
                 'host_assignment_scope')
            changed_assignments.add(old.targets[0].id)
        else:
            need(isinstance(old, ast.FunctionDef) and isinstance(new, ast.FunctionDef) and
                 old.name == new.name and old.name in allowed, 'host_method_scope')
            changed_methods.add(old.name)
    need(changed_assignments == set(replacements) and changed_methods == allowed, 'host_exact_edit_inventory')
    return raw, dict(whole_byte_ast_inverse=True, other_host_definitions_byte_exact=True,
        finite_substitutions=len(steps), changed_assignments=sorted(changed_assignments), changed_methods=sorted(changed_methods))


def prepare(inputs=None, evidence=None):
    """Pure assembly; no SOURCE/result write, main, Stage or runtime method."""
    inputs = {} if inputs is None else inputs
    reader = reader_module()
    retain(reader, inputs, READER, evidence)
    for row in PREPARE_PINS:
        retain(reader, inputs, row, evidence)
    previous = pure_module(inputs[MOTHER[0]], MOTHER[0], '_send_http_cap_v1_status_pure', PREPARE_NAMES)
    old_module, origin = previous.prepare()
    need(old_module.UI_FIELDS == UI_FIELDS and old_module.UI_BOOLS == UI_BOOLS and
         old_module.SESSION == SESSION and old_module.BUNDLE == BUNDLE, 'measured_ui_contract')
    raw, proof = derive(origin)
    value = types.ModuleType('_send_http_cap_v1_derived_host_source')
    value.__file__ = str(BASE / SELF)
    exec(compile(raw, '<send-http-cap-v1-derived-source>', 'exec'), value.__dict__)
    # This new source callback is available in the derived artifact, but its
    # original derived main is never dispatched by this SOURCE-only parent.
    def boundary(snapshot, helper, validator):
        ignored, facts = package_boundary(reader, snapshot, evidence)
        return facts['full_package_byte_inverse']
    value._STATUS_UI_SOURCE_BOUNDARY = boundary
    need(value.WORKER == WORKER and value.GUARDIAN == GUARDIAN and value.OUTER == OUTER and
         value.VALIDATOR == VALIDATOR and value.SOURCE_BASELINES == SOURCE_BASELINES and
         value.UI_FIELDS == UI_FIELDS and value.UI_BOOLS == UI_BOOLS, 'final_source_bindings')
    return value, raw, proof, reader, inputs


def main():
    need(sys.platform == 'win32' and BASE == Path(r'D:\project\P011\working\MtaP011-v0.1') and
         Path(sys.executable) == Path(r'C:\Users\P011_USER\AppData\Local\Programs\Python\Python312\python.exe'),
         'fixed_pc_source_entry')
    reader = reader_module()
    sealer_raw = reader.read_fixed(SEALER[0], SEALER[1:])
    sealer = types.ModuleType('_send_http_cap_v1_artifact_sealer')
    exec(compile(sealer_raw, '<send-http-cap-v1-artifact-sealer>', 'exec'), sealer.__dict__)
    out = BASE / 'results' / ('formal-send-fc-http-cap-v1-source-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs = {SEALER[0]: sealer_raw}
    evidence = sealer.InputEvidence(inputs)
    report = dict(schema='p011-formal-send-fc-http-cap-v1-host-source', mode='SOURCE_ONLY', passed=False,
        source_checked=False, source_preserved=False, snapshots_preserved=False, error=None,
        input_count=1, stage_option_connected=False, control_option_connected=False, device_option_connected=False,
        requested_options=list(sys.argv[1:]), stage_invoked=False, control_invoked=False, device_invoked=False,
        ui_invoked=False, owner_invoked=False, runtime_invoked=False, automatic_rf_action=False, rf_invoked=False,
        phone_tested=False, stock_restoration_verified=False, full_owner_closure_verified=False,
        filecenter_parent_deadline_verified=False, actual_p011=False, old_mains_called=0,
        old_tests_run=0, generator_called=False, ui_rebuilt=False, original_results=17,
        original_window_seconds=600, original_cleanup_seconds=60, original_smoke_seconds=20,
        original_carrier_seconds=800, original_host_timeout_seconds=810,
        carrier_metadata_fixture_is_authority=False, new_ordinary_root_runtime_observed=False)
    try:
        for path in (SELF, CMD):
            evidence._retain(path, reader.read_fixed(path))
        need(not sys.argv[1:], 'device_stage_control_not_connected' if any(
             item in DISCONNECTED_OPTIONS for item in sys.argv[1:]) else 'source_only_no_arguments')
        value, raw, proof, reader, ignored = prepare(inputs, evidence)
        fc_rows, closure = package_boundary(reader, inputs, evidence)
        program, wire = value.ui_program(inputs, fc_rows)
        need(type(program) is bytes and type(wire) is bytes and 0 < len(program) <= 2097152 and
             0 < len(wire) <= 4194304 and max(map(len, program.splitlines())) <= 2048, 'ui_wire_caps')
        ast.parse(program, feature_version=(3, 5))
        carrier_pin = value.CARRIER_HELPER
        carrier_raw = retain(reader, inputs, carrier_pin, evidence)
        body = value.carrier_body(types.SimpleNamespace(CARRIER_BODY=literal(carrier_raw, 'CARRIER_BODY')))
        metadata_fixture = (18446744073709551615, 17361641481138401520, 16832, 0, 0, 2,
                            16276538888567251425, 15191436295996101330, 14106333703424951235)
        files_fixture = (('bootstrap.py', metadata_fixture), ('wire.raw', metadata_fixture[::-1]))
        payload_pins = ((len(program), digest(program)), (len(wire), digest(wire)))
        carrier_sources = []
        for phase in ('create', 'launch', 'inspect'):
            source = value.carrier_source(body, phase, 'p011-mta-ui-carrier-v4-' + 'f' * 24, payload_pins,
                None if phase == 'create' else metadata_fixture, files_fixture if phase == 'inspect' else None)
            ast.parse(source, feature_version=(3, 5))
            need(max(map(len, source.splitlines())) <= 2048, 'carrier_line_cap')
            command = value.carrier_command(source)
            sealer.fresh(out / ('private-raw/carrier-' + phase + '.source.py'), source.encode('ascii'))
            carrier_sources.append(dict(phase=phase, bytes=len(source), sha256=digest(source.encode('ascii')),
                                        command_bytes=len(command.encode('ascii'))))
        for name, data in (('derived-host.py', raw), ('ui-bootstrap.py', program), ('ui-wire.raw', wire)):
            sealer.fresh(out / ('private-raw/' + name), data)
        report.update(source_checked=True, package_closure=closure, derived_host_proof=proof,
            derived_host_bytes=len(raw), derived_host_sha256=digest(raw),
            ui_bootstrap_bytes=len(program), ui_bootstrap_sha256=digest(program),
            ui_wire_bytes=len(wire), ui_wire_sha256=digest(wire), carrier_sources=carrier_sources)
        report['passed'] = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ':' + str(error)[:180]
        sealer.fresh(out / 'private-raw/exception.txt', traceback.format_exc().encode('utf-8'))
    finally:
        try:
            evidence.snapshot(out, lambda key: key)
            report['input_count'] = len(inputs)
            report['source_preserved'] = not evidence.partial and all(
                reader.read_fixed(path) == raw for path, raw in inputs.items())
            report['snapshots_preserved'] = all((out / 'private-inputs' / path).read_bytes() == raw
                                               for path, raw in inputs.items())
            need(report['source_preserved'] and report['snapshots_preserved'], 'source_preservation')
        except BaseException as error:
            report['passed'] = False
            report['error'] = report['error'] or type(error).__name__ + ':' + str(error)[:180]
            sealer.fresh(out / 'private-raw/preservation-exception.txt', traceback.format_exc().encode('utf-8'))
    readme = (b'SOURCE-only new sender HTTP-cap HOST/carrier linkage; no device option is connected.\n'
        b'Actual new Boot/Owner/Outer/Stage/Worker/Guardian/FC9/ordinary manifest and 19 unchanged GUI files.\n'
        b'Pure measured status HOST preparation; complete finite byte/AST inverse, no old main/test/generator.\n'
        b'Original 17 results, smoke20, UI600+cleanup60, carrier800/HOST810 and guardian/finally remain source.\n'
        b'Carrier metadata samples are PC syntax/cap fixtures, never device authority.\n'
        b'New ordinary Stage, CONTROL and device UI remain explicitly disconnected/unverified.\n'
        b'No ADB, runtime, credentials, GUI rebuild/restage, RF or phone action.\n'
        b'Private source/wire/input snapshots retained; public result commits only after private ZIP verification.\n')
    result = sealer.seal_result(out, report, readme)
    print(json.dumps(dict(passed=result['report']['passed'], output=str(out),
        archive=str(result['archive']) if result['archive'] else None, archive_sha256=result['archive_sha256'],
        error=result['report']['error']), ensure_ascii=True))
    return result['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
