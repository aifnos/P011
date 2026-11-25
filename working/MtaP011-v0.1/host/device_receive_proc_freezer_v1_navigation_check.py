"""Actual Proc/freezer graph over the frozen 51-field navigation carrier.

Default SOURCE or explicit navigation-test only; there is no staging entry.
Finite byte/AST overlay proofs and pure carrier/READY/capture algorithms are
reused, never an archived main/full graph verifier/suite/generator. The new
flat graph alone verifies its actual75/208 origins/FC9. GUI20 stays exact.
"""
import ast
import copy
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import sys
import traceback
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_proc_freezer_v1_navigation_check.py'
CMDS = ('HOST_MTA_RECEIVE_PROC_FREEZER_V1_NAVIGATION_SOURCE_CHECK.cmd',
        'TEST_MTA_RECEIVE_PROC_FREEZER_V1_NAVIGATION.cmd')
CURRENT = ('host/device_receive_proc_identity_diff_v1_check.py', 17053,
           'b0289d406328d85e9f9fb726c0ce160bffa84f5abe167d346c22e0093d38c4d6')
DURABLE_UI = ('host/device_formal_receive_durable_ui_v1_check.py', 25979,
              'f870215893a5fd9a8317e76f5c5b0d3fa4971269c862d9d1e9f603709b4260dd')
DEFINITIONS = ('host/formal_receive_proc_freezer_v1_definitions.py', 114824,
               '3eb522f95f199a1efea2c2d1505a76ab6677f7f1f419e54d64d5a0866cafc21a')
CORE_RUNNER = ('candidate/receive-proc-freezer-v1/runtime/mta_formal_receive_session.py', 79279,
               '68573f0c9053db3df42f71647d9765a6af9bda56f4913daeef52b79e907f1894')
NAVIGATION_RUNNER = ('candidate/receive-proc-freezer-v1/runtime/mta_formal_receive_navigation_session.py', 88850,
                     '9d2244fb49058077d947f95b514c921b2fd62c2285c00147edce07523c2a8963')
WORKER = ('candidate/receive-proc-freezer-v1/runtime/ui_session.py', 100157,
          '06196ee0567dd5e3076638a3821974985e5b771497922eb0ee7ecdf916ab0697')
VALIDATOR = ('candidate/formal-receive-durable-state-gui-v1/runtime/ui_assets.py', 12798,
             '67e3d2d1bd7654cde6993d9746c8dd2cb3447676f0fb0f4bb2dec4a2ffb8d1bb')
BASE_UI_RUNNER = ('candidate/formal-receive-durable-ui-v1/runtime/mta_formal_receive_session.py', 88773,
                  'a5dffa34a9dac7fdcc240dd59e1472448dbe7f076ec5d1240804401cbaa1c0a3')
OLD_WINDOW_RUNNER = ('candidate/receive-window-clock-v1/runtime/mta_formal_receive_navigation_session.py', 88850,
                     '2aa5c840d9df5293fe10d385060821269d5170da4261b751c49af091ccf31f48')
OLD_ATOMIC_WORKER = ('candidate/receive-navigation-atomic-v1/runtime/ui_session.py', 100162,
                     'cde8ae626632e5d86acb2cc741b7d22eb18582b58ed6d6fd48160c008b62225e')
PROC = ('host/receive_startup_proc_projection_v1.py', 6137,
        'aae15e0726ae21c2d1f8b97e8249123465c67191e2928f607e149acadd264002')
PROC_IDENTITY = ('host/receive_startup_proc_identity_diff_v1.py', 16789,
                 '6712eaadd8bab1b29e1eeed3854bfe35b56c52b2d605adf31521c6e44e99eafa')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
ROOT_NAME = 'p011-mta-rx-freezer-v1'
SESSION = '559c72ccf8f8ff1b7fc83fb6'
PAYLOAD_BYTES, ORIGIN_COUNT, CLOSURES = 4191766, 208, 8
OLD_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-receive-proc-identity-diff-v1'"
NEW_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-receive-proc-freezer-v1'"
RETURNED = b'component=worker.run_fixed(sources["runner"],tuple(artifacts),sources["assets"],navigation_test=True,filecenter_sources=tuple(fc))\n'
RESULT = b'print("RESULT="+repr(component));print("MTA_REMOTE_OK")\n'
READ_ME = (b'Actual Proc/freezer runtime75/4191766 over the frozen current pure navigation carrier.\n'
           b'Default SOURCE or explicit navigation-test only; no staging entry or automatic RF/phone/file action.\n'
           b'New graph alone verifies208 actual origins,8 mechanical+1 Proc business closures,7 changed/68 exact roles.\n'
           b'Only Proc stable_key masks PF_FREEZER_SKIP; raw flags/other bits/IO/guards/deadlines remain original.\n'
           b'Other graph changes are independent freezer root and actual pin propagation; client-rfinit stays exact.\n'
           b'Existing GUI20/session/validator/4192479 and FC9/113690 are reused, never rebuilt/restaged.\n'
           b'Finite frozen byte/AST overlay proofs supply carrier algorithms; no old full graph verifier/main/suite/build runs.\n'
           b'Original51/PASS/finally/stock restore/capture/READY/QtTest/watch/DRM and private diagnostics stay strict.\n'
           b'Original run_fixed1246/refusal1560/Runner817 remain; Proc identity DATA stays adjacent to original PROC.\n'
           b'New actual runner/worker encoded blocks and HOST CONTROL are complete byte/AST inverse overlays.\n'
           b'Caps10/600+60/20/READY10/800/HOST810,bootstrap2MiB,line2048,wire6MiB,HOST26KiB stay.\n'
           b'Raw inputs/streams/exit receipts/images precede metadata-only publication in private evidence.\n'
           b'SOURCE is not P011 navigation/physical output/phone transfer/RF/receive admission/full restoration acceptance.\n')
HOST_INPUTS, EXTERNAL_INPUTS, FACTS = {}, {}, {}
SEAL = EVIDENCE = EXTERNAL_EVIDENCE = HOST_OUT = None


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def shape(node):
    return ast.dump(node, include_attributes=False)


def fixed(pin):
    return EVIDENCE.read(BASE / pin[0], key=pin[0], pin=pin[1:])


def current_pure():
    tree = ast.parse(fixed(CURRENT), feature_version=(3, 5))
    nodes = [row for row in tree.body if isinstance(row, (ast.Import, ast.ImportFrom, ast.Assign)) or
             isinstance(row, (ast.FunctionDef, ast.ClassDef)) and row.name != 'main']
    need(all(not row.decorator_list for row in nodes if isinstance(row, (ast.FunctionDef, ast.ClassDef))),
         'pure_definition_shape')
    value = types.ModuleType('fixed_freezer_navigation_proc_identity_pure')
    value.__file__ = str(BASE / CURRENT[0])
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                 value.__file__, 'exec'), value.__dict__)
    need('main' not in value.__dict__ and value.SELF == CURRENT[0] and
         value.WORKER == OLD_ATOMIC_WORKER and value.SEALER == SEALER and
         value.PROC == PROC and value.DIAGNOSTIC == PROC_IDENTITY, 'current_pure_identity')
    for name in ('HOST_INPUTS', 'EXTERNAL_INPUTS', 'FACTS', 'SEAL', 'EVIDENCE',
                 'EXTERNAL_EVIDENCE', 'HOST_OUT', 'READ_ME'):
        value.__dict__[name] = globals()[name]
    return value


def main_overlay(tree):
    before = copy.deepcopy(tree)
    rows = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and len(row.targets) == 1 and
            isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'control']
    need(len(rows) == 1 and shape(rows[0].value) == shape(ast.parse(OLD_CONTROL, mode='eval').body),
         'main_original_identity_diff_control')
    original = rows[0].value
    rows[0].value = ast.parse(NEW_CONTROL, mode='eval').body
    final = copy.deepcopy(tree)
    rows[0].value = original
    need(shape(tree) == shape(before), 'freezer_main_complete_ast_inverse')
    FACTS['proc_freezer_main_complete_ast_inverse_verified'] = True
    return ast.fix_missing_locations(final)


def finalize_overlay(original):
    """One metadata label delta; the entire original private-first seal stays."""
    raw = fixed(DURABLE_UI)
    rows = [row for row in ast.parse(raw, feature_version=(3, 5)).body
            if isinstance(row, ast.FunctionDef) and row.name == 'finalize']
    need(len(rows) == 1 and not rows[0].decorator_list and
         type(original) is types.FunctionType and original.__code__.co_firstlineno == rows[0].lineno and
         original.__code__.co_filename == str(BASE / DURABLE_UI[0]), 'finalize_original_binding')
    before = copy.deepcopy(rows[0])
    labels = [row for row in ast.walk(rows[0]) if isinstance(row, ast.keyword) and row.arg == 'source_graph']
    need(len(labels) == 1 and isinstance(labels[0].value, ast.Constant) and
         labels[0].value.value == 'durable-state-v1', 'finalize_original_label')
    old = labels[0].value.value
    labels[0].value.value = 'receive-proc-freezer-v1'
    final = copy.deepcopy(rows[0])
    labels[0].value.value = old
    need(shape(rows[0]) == shape(before), 'finalize_complete_ast_inverse')
    namespace = types.ModuleType('fixed_freezer_navigation_finalize')
    namespace.__dict__.update(original.__globals__)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[final], type_ignores=[])),
                 str(BASE / SELF), 'exec'), namespace.__dict__)
    FACTS['proc_freezer_finalize_metadata_only_ast_inverse_verified'] = True
    return namespace.finalize


def graph_payload(graph, read, inputs, fc):
    """Only the new flat graph's current exact delta, never an old verifier."""
    need(type(graph) is types.ModuleType and graph.__file__ == str(BASE / DEFINITIONS[0]) and
         graph.RUNNER == CORE_RUNNER and graph.NAVIGATION_RUNNER == NAVIGATION_RUNNER and
         graph.WORKER == WORKER and graph.GUI_VALIDATOR == VALIDATOR and graph.SESSION == SESSION and
         graph.STATE_ROOT == '/var/volatile/tmp/' + ROOT_NAME and graph.STATE_ALIAS == '/tmp/' + ROOT_NAME and
         graph.PAYLOAD_BYTES == PAYLOAD_BYTES and len(graph.ORIGIN_SOURCE_PINS) == ORIGIN_COUNT and
         graph.MECHANICAL_CLOSURE_COUNT == CLOSURES and graph.BUSINESS_CLOSURE_COUNT == 1 and
         inputs is HOST_INPUTS, 'actual_freezer_graph')
    for pin in graph.ORIGIN_SOURCE_PINS + (graph.MANIFEST, graph.PRIVATE_MANIFEST, graph.RUNNER,
            graph.NAVIGATION_RUNNER, graph.WORKER, graph.DELTA_SPEC, graph.GENERATION,
            graph.ORIGINAL_MANIFEST, graph.OLD_PRIVATE_MANIFEST):
        read(pin)
    ordinary = graph.manifest_rows(inputs[graph.MANIFEST[0]])
    private_rows = graph.manifest_rows(inputs[graph.PRIVATE_MANIFEST[0]], private=True)
    payload = ordinary + graph.HELPERS + private_rows + (graph.WPA, graph.MONITOR)
    need(len(ordinary) == len(private_rows) == 35 and len(payload) == 75 and
         len({row[0] for row in payload}) == 75 and
         sum(row[2] for row in payload) == PAYLOAD_BYTES <= 4194304, 'actual_freezer_payload_inventory')
    for name, path, size, sha in payload:
        read((path, size, sha))
    fc_rows = graph.FILECENTER_SOURCE_PINS
    need(type(fc) is types.ModuleType and type(fc_rows) is tuple and len(fc_rows) == 9 and
         sum(row[2] for row in fc_rows) == 113690 <= 131072, 'original_filecenter_inventory')
    for name, path, size, sha in fc_rows:
        read((path, size, sha))
    need(graph.verify_inputs(inputs) == CLOSURES, 'new_eight_mechanical_closures')
    fc.FC_ROWS = fc_rows
    entries = [entry for entry in graph.MECHANICAL_EXPECTED if entry['name'] == 'mta_client_receive_factory']
    need(len(entries) == 1, 'actual_factory_unique_pin')
    factory_pin = tuple(entries[0]['candidate'])
    factory = ast.parse(inputs[factory_pin[0]], feature_version=(3, 5))
    methods = [row for node in factory.body if isinstance(node, ast.ClassDef) and
               node.name == 'FixedReceiveDeploymentFactory' for row in node.body if
               isinstance(row, ast.FunctionDef) and row.name == 'startup_readonly']
    need(len(methods) == 1 and sum(isinstance(row, ast.Call) and row.lineno == 1379 and
         shape(row.func) == shape(ast.parse('scope.check_active', mode='eval').body)
         for row in ast.walk(methods[0])) == 1, 'original_factory_diagnostic_callsite')
    FACTS.update(proc_freezer_graph_payload_verified=True,
        proc_freezer_original_graph_payload_called=False, proc_freezer_old_full_graph_verifier_called=False,
        proc_freezer_payload_roles=75, proc_freezer_ordinary_roles=35, proc_freezer_private_roles=35,
        proc_freezer_payload_bytes=PAYLOAD_BYTES, proc_freezer_payload_remaining_bytes=4194304 - PAYLOAD_BYTES,
        proc_freezer_origin_pins=ORIGIN_COUNT, proc_freezer_mechanical_closures=CLOSURES,
        proc_freezer_business_closures=1, proc_freezer_changed_roles=7, proc_freezer_unchanged_roles=68,
        proc_freezer_filecenter_sources=9, proc_freezer_filecenter_bytes=113690,
        proc_freezer_actual_factory_diagnostic_callsite_retained=True)
    return payload


def mother_worker():
    """Reconstruct only the pinned prior CONTROL derivation, never execute it."""
    old = fixed(OLD_ATOMIC_WORKER)
    before = b"CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-receive-navigation-atomic-v1'\n"
    after = b"CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-receive-proc-identity-diff-v1'\n"
    need(old.count(before) == 1, 'mother_worker_original_control_line')
    raw = old.replace(before, after, 1)
    need(raw.count(after) == 1 and raw.replace(after, before, 1) == old, 'mother_worker_control_byte_inverse')
    return raw, (len(raw), digest(raw))


def overlay_program(original, inputs, payload, runner, carrier, fresh):
    need(runner == NAVIGATION_RUNNER and inputs is HOST_INPUTS and len(payload) == 75 and
         sum(row[2] for row in payload) == PAYLOAD_BYTES, 'new_navigation_target_identity')
    # The frozen Window layer requires its base UI Runner while making the mother
    # carrier. Its final encoded Window Runner and prior derived Worker are then
    # replaced by the independently generated actual freezer sources below.
    raw, wire = original(inputs, payload, BASE_UI_RUNNER, carrier)
    old_worker, old_pin = mother_worker()
    def block(name, value, source_pin):
        return ('sources[' + repr(name) + ']=decode((\n' + carrier.encoded(value) +
                '),' + repr(source_pin[0]) + ',' + repr(source_pin[1]) + ')').encode('ascii')
    new_worker, new_runner = fixed(WORKER), fixed(NAVIGATION_RUNNER)
    need(inputs[WORKER[0]] == new_worker and inputs[NAVIGATION_RUNNER[0]] == new_runner and
         inputs[OLD_WINDOW_RUNNER[0]] == fixed(OLD_WINDOW_RUNNER), 'target_exact_input_binding')
    edits = ((block('runner', inputs[OLD_WINDOW_RUNNER[0]], OLD_WINDOW_RUNNER[1:]),
              block('runner', new_runner, NAVIGATION_RUNNER[1:])),
             (block('worker', old_worker, old_pin), block('worker', new_worker, WORKER[1:])))
    value = raw
    for before, after in edits:
        need(value.count(before) == 1, 'freezer_target_overlay_count')
        value = value.replace(before, after, 1)
    inverse = value
    for before, after in reversed(edits):
        need(inverse.count(after) == 1, 'freezer_target_inverse_count')
        inverse = inverse.replace(after, before, 1)
    need(inverse == raw and shape(ast.parse(inverse, feature_version=(3, 5))) ==
         shape(ast.parse(raw, feature_version=(3, 5))) and len(value) <= 2097152 and
         max(map(len, value.splitlines())) <= 2048 and len(wire) <= 6291456,
         'freezer_target_complete_byte_ast_inverse_budget')
    proc_tree, identity_tree = (ast.parse(fixed(pin), feature_version=(3, 5)) for pin in (PROC, PROC_IDENTITY))
    fragments = []
    for tree in (proc_tree, identity_tree):
        rows = [row.value for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
                isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'TARGET_FRAGMENT']
        need(len(rows) == 1, 'original_diagnostic_literal_shape')
        fragments.append(ast.literal_eval(rows[0]))
    proc, identity = fragments
    need(raw.count(RETURNED) == value.count(RETURNED) == raw.count(RESULT) == value.count(RESULT) == 1 and
         raw.count(proc + identity) == value.count(proc + identity) == 1 and
         value.index(RETURNED) + len(RETURNED) <= value.index(proc) and
         value.index(proc) + len(proc) == value.index(identity) and
         value.index(identity) + len(identity) < value.index(RESULT) and
         raw.count(b'tb.tb_lineno!=1560') == value.count(b'tb.tb_lineno!=1560') == 1 and
         raw.count(b'code.co_firstlineno!=817') == value.count(b'code.co_firstlineno!=817') == 1,
         'original_diagnostics_return_refusal_order')
    ast.parse(value, feature_version=(3, 5))
    fresh(HOST_OUT / 'private-mother-proc-identity-navigation-bootstrap.py', raw)
    fresh(HOST_OUT / 'private-mother-proc-identity-navigation-wire.raw', wire)
    fresh(HOST_OUT / 'private-freezer-overlay-mother-worker.py', old_worker)
    FACTS.update(proc_freezer_carrier_complete_byte_ast_inverse_verified=True,
        proc_freezer_prior_derived_worker_pin=list(old_pin), proc_freezer_worker_pin=list(WORKER),
        proc_freezer_navigation_runner_pin=list(NAVIGATION_RUNNER),
        proc_freezer_only_runner_worker_encoded_blocks_changed=True,
        proc_freezer_original_diagnostics_unchanged=True, proc_freezer_proc_identity_adjacency_preserved=True,
        proc_freezer_original_refusal1560_runner817_preserved=True,
        proc_freezer_program_bytes=len(value), proc_freezer_program_max_line=max(map(len, value.splitlines())),
        proc_freezer_wire_bytes=len(wire), proc_freezer_gui_rebuilt=False, proc_freezer_gui_restaged=False)
    return value, wire


def prepare():
    current = current_pure()
    original_overlay = current.main_overlay
    current.main_overlay = lambda tree: main_overlay(original_overlay(tree))
    driver = current.prepare()  # Finite pure composition/proofs only; old main is absent.
    need(len(driver.UI_FIELDS) == 51 and driver.NEW_RUNNER == BASE_UI_RUNNER and
         driver.WORKER[0] == 'candidate/formal-receive-durable-ui-v1/runtime/ui_session.py' and
         len(HOST_INPUTS[SELF]) <= 26624, 'original_driver_identity_schema_budget')
    original_graph = driver.graph_payload
    need(type(original_graph) is types.FunctionType and original_graph.__code__.co_firstlineno == 206 and
         original_graph.__code__.co_filename == str(BASE / DURABLE_UI[0]), 'original_graph_function_identity')
    nav = original_graph.__globals__.get('NAV')
    need(type(nav) is types.ModuleType and type(nav.FC) is types.ModuleType, 'original_filecenter_scope')
    fc = nav.FC
    driver.graph_payload = lambda graph, read, inputs: graph_payload(graph, read, inputs, fc)
    original_program = driver.ui_program
    driver.ui_program = lambda inputs, payload, runner, carrier: overlay_program(
        original_program, inputs, payload, runner, carrier, driver.write_new)
    driver.finalize = finalize_overlay(driver.finalize)
    # Actual final main inventory is new. The already-captured pure mother
    # carrier namespaces keep their old identity pins for complete inverse.
    driver.DEFINITIONS, driver.WORKER, driver.NEW_RUNNER = DEFINITIONS, WORKER, NAVIGATION_RUNNER
    driver.RUNTIME, driver.PAYLOAD_BYTES = 'candidate/receive-proc-freezer-v1/runtime/', PAYLOAD_BYTES
    driver.READ_ME = READ_ME
    for pin in (DEFINITIONS, CORE_RUNNER, NAVIGATION_RUNNER, WORKER, VALIDATOR):
        fixed(pin)
    FACTS.update(proc_freezer_finite_static_overlay_proofs_reused=True,
        proc_freezer_old_full_graph_verifier_called=False, proc_freezer_old_main_called=False,
        proc_freezer_old_suite_called=False, proc_freezer_generator_called=False,
        proc_freezer_source_graph='receive-proc-freezer-v1', proc_freezer_runtime_root=ROOT_NAME,
        proc_freezer_stage_entry_available=False, proc_freezer_gui_session=SESSION,
        proc_freezer_gui_files=20, proc_freezer_gui_bytes=4192479,
        proc_freezer_public_fields=51, proc_freezer_bootstrap_cap=2097152,
        proc_freezer_wire_cap=6291456, proc_freezer_host_cap=26624,
        proc_freezer_startup_seconds=10, proc_freezer_owner_seconds=600, proc_freezer_cleanup_seconds=60,
        proc_freezer_navigation_seconds=20, proc_freezer_ready_seconds=10,
        proc_freezer_outer_seconds=800, proc_freezer_host_seconds=810)
    return driver


def main():
    global SEAL, EVIDENCE, EXTERNAL_EVIDENCE, HOST_OUT
    need(sys.argv[1:] in ([], ['--navigation-test']) and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'fixed_pc_modes')
    mode = 'navigation-test' if sys.argv[1:] else 'source'
    HOST_OUT = BASE / 'results' / ('receive-proc-freezer-v1-navigation-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    HOST_OUT.mkdir(parents=True, exist_ok=False)
    sealer_raw = (BASE / SEALER[0]).read_bytes()
    need((len(sealer_raw), digest(sealer_raw)) == SEALER[1:], 'fixed_sealer_pin')
    SEAL = types.ModuleType('fixed_freezer_navigation_sealer')
    exec(compile(sealer_raw, str(BASE / SEALER[0]), 'exec'), SEAL.__dict__)
    EVIDENCE, EXTERNAL_EVIDENCE = SEAL.InputEvidence(HOST_INPUTS), SEAL.InputEvidence(EXTERNAL_INPUTS)
    try:
        for path in (SELF,) + CMDS:
            EVIDENCE.read(BASE / path, key=path)
        fixed(SEALER)
        driver = prepare()
    except BaseException as error:
        SEAL.fresh(HOST_OUT / 'private-raw/outer-error.private.txt', traceback.format_exc().encode('utf-8'))
        EVIDENCE.snapshot(HOST_OUT, lambda name: name)
        EXTERNAL_EVIDENCE.snapshot(HOST_OUT / 'private-external', lambda name: name)
        report = dict(passed=False, mode=mode, source_checked=False, source_preserved=False,
            error_kind=type(error).__name__, device_invoked=False, device_execution_unknown=False,
            phone_tested=False, restoration_verified=False, old_graphs=0, old_suites=0, old_builders=0,
            checker_exit=1, integration_facts=dict(FACTS), historical_main_called=False,
            input_pins=[dict(path=name, bytes=len(raw), sha256=digest(raw), complete=name not in EVIDENCE.partial)
                        for name, raw in HOST_INPUTS.items()])
        sealed = SEAL.seal_result(HOST_OUT, report, READ_ME)
        print(json.dumps(dict(passed=False, mode=mode, error_kind=report['error_kind'],
            result_dir=str(HOST_OUT), public_result_zip=str(sealed['archive']) if sealed['archive'] else None,
            zip_sha256=sealed['archive_sha256']), sort_keys=True))
        return sealed['host_exit']
    return driver.main()  # Newly composed original PASS/finally/capture/stock/seal algorithm.


if __name__ == '__main__':
    raise SystemExit(main())
