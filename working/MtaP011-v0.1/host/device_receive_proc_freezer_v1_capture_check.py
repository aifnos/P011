"""Independent capture-only smoke over the already frozen freezer carrier.

SOURCE by default; explicit --capture-only selects the Worker's existing
smoke_only=True launched+20s mode, never QtTest navigation. Actual Worker,
runtime75, GUI20 and FC9 stay exact. Only the held-log WATCH root line is
rebound; all original PID/start/FD/READY/DRM/stock/finally limits remain.
The smoke result naturally has46 fields, not the navigation mode's51.
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
SELF = 'host/device_receive_proc_freezer_v1_capture_check.py'
CMDS = ('HOST_MTA_RECEIVE_PROC_FREEZER_V1_CAPTURE_SOURCE_CHECK.cmd',
        'TEST_MTA_RECEIVE_PROC_FREEZER_V1_CAPTURE.cmd')
CURRENT = ('host/device_receive_proc_freezer_v1_navigation_check.py', 22121,
           'b8fadeabd1b5c675b4e5a631edeacb0301d5bfa691440181a05ca80f7ba28cd6')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
ORIGIN = ('host/device_formal_receive_ui_v1_check.py', 24136,
          'f72c802ab8fbec8cc1e0b228ed8c779dd69752b9fa279ad1b966558c4d095857')
FILECENTER = ('host/device_formal_receive_filecenter_ui_v1_check.py', 16312,
              '2388ba10e035ca42f250af557cfa040cbe2a16a4aa0d19e58027e89d9bba58c0')
READY_DONOR = ('host/device_formal_receive_filecenter_ui_v4_check.py', 18256,
               '5ba3131f34dbcc912dc7d50a058e5a49e644a5583520fa36bdd407460807b556')
SESSION = '559c72ccf8f8ff1b7fc83fb6'
OLD_WATCH_ROOT = '/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-durable-ui-v1'
WATCH_ROOT = '/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-receive-proc-freezer-v1'
CANDIDATE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION + '/Z03.mta-ui-candidate'
NAVIGATION_RETURNED = b'component=worker.run_fixed(sources["runner"],tuple(artifacts),sources["assets"],navigation_test=True,filecenter_sources=tuple(fc))\n'
SMOKE_RETURNED = b'component=worker.run_fixed(sources["runner"],tuple(artifacts),sources["assets"],smoke_only=True,filecenter_sources=tuple(fc))\n'
NAVIGATION_BOOLS = ('navigation_test_requested', 'navigation_display_finished',
                    'navigation_cancelled_empty_observed', 'navigation_receive_activity_free')
FILECENTER_FIELDS = ('filecenter_constructed', 'filecenter_credentials_issued',
                     'filecenter_close_called', 'filecenter_closed', 'filecenter_http_observed',
                     'filecenter_guardian_bound', 'filecenter_audio_settled')
READ_ME = (b'Independent SOURCE or explicit capture-only20-second existing Worker smoke profile.\n'
           b'Frozen freezer navigation pure prepare supplies finite composition only; no archived main/test/suite/build.\n'
           b'Actual Worker/runtime75/GUI20/FC9 remain byte-exact; only its existing smoke_only entry is selected.\n'
           b'No QtTest navigation, receive cancellation, file-page click or prior PASS replay occurs.\n'
           b'Only the WATCH complete root assignment changes durable-UI to the actual freezer CONTROL directory.\n'
           b'Complete WATCH byte/AST inverse retains candidate exe, PID/start double-read, FD/inode/type/mode/READY gates.\n'
           b'Complete final target call byte/AST inverse selects smoke_only=True instead of navigation_test=True.\n'
           b'Natural smoke46 fields equal frozen navigation51 minus its five conditional navigation fields.\n'
           b'Frozen original UI smoke acceptance plus original FileCenter7 and capture.complete stay strict.\n'
           b'No fake navigation fields or receipt are generated; this is not a navigation revalidation.\n'
           b'Main mode/program-key/receipt-only gate delta has a complete AST inverse; original finally/stock/seal stay.\n'
           b'Caps startup10/Owner600+60/display20/READY10/outer800/HOST810/target2MiB/line2048/wire6MiB stay.\n'
           b'Original WATCH alarm70/read65/HOST75 and read-only DRM target12/HOST20 remain unchanged.\n'
           b'Raw actual inputs/streams/exit receipts/WATCH sources/images are private before metadata-only publication.\n'
           b'SOURCE is not P011 output; capture is not touch/phone/transfer/RF/full wireless restoration acceptance.\n')
HOST_INPUTS, EXTERNAL_INPUTS, FACTS = {}, {}, {}
SEAL = EVIDENCE = EXTERNAL_EVIDENCE = HOST_OUT = None


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def shape(node):
    return ast.dump(node, include_attributes=False)


def expression(source):
    return ast.parse(source, mode='eval').body


def fixed(pin):
    return EVIDENCE.read(BASE / pin[0], key=pin[0], pin=pin[1:])


def current_pure():
    tree = ast.parse(fixed(CURRENT), feature_version=(3, 5))
    nodes = [row for row in tree.body if isinstance(row, (ast.Import, ast.ImportFrom, ast.Assign)) or
             isinstance(row, (ast.FunctionDef, ast.ClassDef)) and row.name != 'main']
    need(all(not row.decorator_list for row in nodes if isinstance(row, (ast.FunctionDef, ast.ClassDef))),
         'pure_definition_shape')
    value = types.ModuleType('fixed_freezer_capture_navigation_pure')
    value.__file__ = str(BASE / CURRENT[0])
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                 value.__file__, 'exec'), value.__dict__)
    need('main' not in value.__dict__ and value.SELF == CURRENT[0] and
         value.SESSION == SESSION and value.SEALER == SEALER, 'capture_current_pure_identity')
    for name in ('HOST_INPUTS', 'EXTERNAL_INPUTS', 'FACTS', 'SEAL', 'EVIDENCE',
                 'EXTERNAL_EVIDENCE', 'HOST_OUT', 'READ_ME'):
        value.__dict__[name] = globals()[name]
    return value


def capture_main(tree):
    """Mode-only outer delta; retain the entire original carrier/finally body."""
    before = copy.deepcopy(tree)
    need(len(tree.body) == 1 and isinstance(tree.body[0], ast.FunctionDef) and
         tree.body[0].name == 'main', 'capture_main_single_definition')
    body = tree.body[0].body
    edits = []
    def change(parent, field, value):
        old = parent[field] if type(parent) is list else getattr(parent, field)
        edits.append((parent, field, copy.deepcopy(old)))
        if type(parent) is list:
            parent[field] = value
        else:
            setattr(parent, field, value)
    def report_assignment(row, key):
        return (isinstance(row, ast.Assign) and len(row.targets) == 1 and
                isinstance(row.targets[0], ast.Subscript) and
                isinstance(row.targets[0].value, ast.Name) and row.targets[0].value.id == 'report' and
                isinstance(row.targets[0].slice, ast.Constant) and row.targets[0].slice.value == key)
    passes = [row for row in body if report_assignment(row, 'passed')]
    receipts = [row for row in body if report_assignment(row, 'navigation_receipt') or
                report_assignment(row, 'navigation_receipt_verified')]
    receipt_jobs = [row for row in body if isinstance(row, ast.If) and
                    shape(row.test) == shape(expression("mode == 'navigation-test'"))]
    need(len(passes) == 1 and len(receipts) == 2 and len(receipt_jobs) == 1 and
         isinstance(passes[0].value, ast.BoolOp) and isinstance(passes[0].value.op, ast.And) and
         len(passes[0].value.values) == 2 and
         shape(passes[0].value.values[1]) == shape(expression(
             "mode != 'navigation-test' or report.get('navigation_receipt_verified') is True and READY_CAPTURE.complete()")),
         'capture_original_navigation_completion')
    need(all(isinstance(row.value, ast.Constant) for row in receipts) and
         {shape(row.value) for row in receipts} == {shape(expression('None')), shape(expression('False'))} and
         sum(isinstance(row, ast.Call) and shape(row.func) == shape(expression('navigation_receipt'))
             for row in ast.walk(receipt_jobs[0])) == 1, 'capture_receipt_only_job')
    change(passes[0].value.values, 1, expression("mode != 'capture-only' or READY_CAPTURE.complete()"))
    for row in receipts + receipt_jobs:
        change(body, body.index(row), ast.Pass())
    counters = dict(argument=0, mode=0, attributes=0)
    for row in list(ast.walk(tree)):
        if isinstance(row, ast.Constant) and row.value == '--navigation-test':
            change(row, 'value', '--capture-only'); counters['argument'] += 1
        elif isinstance(row, ast.Constant) and row.value == 'navigation-test':
            change(row, 'value', 'capture-only'); counters['mode'] += 1
        elif (isinstance(row, ast.Attribute) and isinstance(row.value, ast.Name) and
                row.value.id == 'args' and row.attr == 'navigation_test'):
            change(row, 'attr', 'capture_only'); counters['attributes'] += 1
    need(counters == dict(argument=1, mode=5, attributes=4), 'capture_main_fixed_mode_delta')
    # No other explicit device mode is exposed by the final parser.
    arguments = [row for row in ast.walk(tree) if isinstance(row, ast.Call) and
                 shape(row.func) == shape(expression('modes.add_argument'))]
    need(len(arguments) == 1 and len(arguments[0].args) == 1 and
         shape(arguments[0].args[0]) == shape(expression("'--capture-only'")),
         'capture_only_parser')
    final = copy.deepcopy(tree)
    for parent, field, old in reversed(edits):
        if type(parent) is list:
            parent[field] = old
        else:
            setattr(parent, field, old)
    need(shape(tree) == shape(before), 'capture_main_complete_ast_inverse')
    FACTS.update(capture_main_complete_ast_inverse_verified=True,
                 capture_navigation_receipt_requested=False,
                 capture_completion_gate_retained=True, capture_finally_stock_body_retained=True)
    return ast.fix_missing_locations(final)


def watch_overlay(capture, worker_raw):
    """Rebind one complete root line, never the candidate or watcher guards."""
    need(type(capture.watch) is str and capture.stream_facts is None and
         capture.side['requested'] is False and capture.side['error_kind'] is None and
         capture.observe.__func__.__code__.co_filename == str(BASE / READY_DONOR[0]),
         'capture_fresh_frozen_ready_binding')
    old = capture.watch.encode('ascii')
    before = ('root=' + repr(OLD_WATCH_ROOT) + '\n').encode('ascii')
    after = ('root=' + repr(WATCH_ROOT) + '\n').encode('ascii')
    need(old.count(before) == 1 and old.count(after) == 0, 'capture_watch_complete_root_line')
    new = old.replace(before, after, 1)
    need(new.count(after) == 1 and new.replace(after, before, 1) == old and
         len(old.splitlines()) == len(new.splitlines()) and len(new) <= 4096 and
         max(map(len, new.splitlines())) <= 2048, 'capture_watch_complete_byte_inverse_budget')
    tree = ast.parse(old, feature_version=(3, 5))
    original = copy.deepcopy(tree)
    roots = [row for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
             isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'root']
    candidates = [row for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
                  isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'candidate']
    need(len(roots) == len(candidates) == 1 and ast.literal_eval(roots[0].value) == OLD_WATCH_ROOT and
         ast.literal_eval(candidates[0].value) == CANDIDATE, 'capture_watch_original_identities')
    roots[0].value = ast.Constant(value=WATCH_ROOT)
    need(shape(tree) == shape(ast.parse(new, feature_version=(3, 5))), 'capture_watch_complete_ast_forward')
    roots[0].value = ast.Constant(value=OLD_WATCH_ROOT)
    need(shape(tree) == shape(original) and shape(ast.parse(new.replace(after, before, 1),
         feature_version=(3, 5))) == shape(original), 'capture_watch_complete_ast_inverse')
    worker = ast.parse(worker_raw, feature_version=(3, 5))
    controls = [row for row in worker.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
                isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'CONTROL_NAME']
    need(len(controls) == 1 and shape(controls[0].value) == shape(expression(
         "'p011-mta-ui-session-' + SESSION + '-receive-proc-freezer-v1'")), 'capture_actual_worker_control')
    # Source bytes, including every predicate and function line, stay exact.
    def functions(raw):
        lines = raw.splitlines(keepends=True)
        return [(row.name, row.lineno, row.end_lineno, b''.join(lines[row.lineno - 1:row.end_lineno]))
                for row in ast.parse(raw, feature_version=(3, 5)).body
                if isinstance(row, (ast.FunctionDef, ast.ClassDef))]
    need(functions(old) == functions(new), 'capture_watch_functions_lines_exact')
    SEAL.fresh(HOST_OUT / 'private-frozen-durable-ui-watch.py', old)
    SEAL.fresh(HOST_OUT / 'private-freezer-capture-watch.py', new)
    capture.watch = new.decode('ascii')
    FACTS.update(capture_watch_complete_byte_ast_inverse_verified=True,
        capture_watch_delta='one_complete_root_assignment_line', capture_watch_root=WATCH_ROOT,
        capture_watch_original_pin=[len(old), digest(old)], capture_watch_actual_pin=[len(new), digest(new)],
        capture_watch_candidate_unchanged=True, capture_watch_pid_start_fd_guards_unchanged=True)


def smoke_program(original, inputs, payload, runner, carrier, fresh):
    """The same actual sources; select the Worker's original smoke entry."""
    raw, wire = original(inputs, payload, runner, carrier)
    need(raw.count(NAVIGATION_RETURNED) == 1 and raw.count(SMOKE_RETURNED) == 0,
         'capture_target_original_navigation_call')
    new = raw.replace(NAVIGATION_RETURNED, SMOKE_RETURNED, 1)
    need(new.count(SMOKE_RETURNED) == 1 and new.replace(SMOKE_RETURNED, NAVIGATION_RETURNED, 1) == raw and
         len(new) <= 2097152 and max(map(len, new.splitlines())) <= 2048 and len(wire) <= 6291456,
         'capture_target_complete_byte_inverse_budget')
    tree = ast.parse(raw, feature_version=(3, 5))
    before = copy.deepcopy(tree)
    calls = [row for row in ast.walk(tree) if isinstance(row, ast.Call) and
             shape(row.func) == shape(expression('worker.run_fixed'))]
    need(len(calls) == 1 and [row.arg for row in calls[0].keywords] ==
         ['navigation_test', 'filecenter_sources'] and shape(calls[0].keywords[0].value) == shape(expression('True')),
         'capture_target_original_keyword')
    calls[0].keywords[0].arg = 'smoke_only'
    need(shape(tree) == shape(ast.parse(new, feature_version=(3, 5))), 'capture_target_complete_ast_forward')
    calls[0].keywords[0].arg = 'navigation_test'
    need(shape(tree) == shape(before) and shape(ast.parse(new.replace(SMOKE_RETURNED, NAVIGATION_RETURNED, 1),
         feature_version=(3, 5))) == shape(before), 'capture_target_complete_ast_inverse')
    fresh(HOST_OUT / 'private-freezer-navigation-mother-bootstrap.py', raw)
    FACTS.update(capture_target_complete_byte_ast_inverse_verified=True,
        capture_target_delta='one_existing_run_fixed_keyword_only', capture_actual_worker_modified=False,
        capture_runtime75_modified=False, capture_gui_rebuilt=False, capture_gui_restaged=False,
        capture_navigation_qttest_requested=False, capture_receive_cancel_requested=False,
        capture_files_page_requested=False, capture_existing_smoke_only_selected=True,
        capture_program_bytes=len(new), capture_program_max_line=max(map(len, new.splitlines())),
        capture_wire_unchanged=True, capture_wire_bytes=len(wire))
    return new, wire


def smoke_bindings(driver):
    """Natural46 parser plus the frozen original smoke/FC7 predicates."""
    need(driver.ORIGIN == ORIGIN and len(driver.UI_FIELDS) == 51 and
         driver.component.__globals__ is driver.__dict__ and
         set(NAVIGATION_BOOLS).issubset(driver.UI_BOOLS) and
         'navigation_display_seconds' in driver.UI_COUNTS and
         set(FILECENTER_FIELDS).issubset(driver.UI_BOOLS), 'capture_original_51_binding')
    origin, fc = fixed(ORIGIN), fixed(FILECENTER)
    definitions = []
    for raw in (origin, fc):
        rows = [row for row in ast.parse(raw, feature_version=(3, 5)).body
                if isinstance(row, ast.FunctionDef) and row.name == 'accepted']
        need(len(rows) == 1 and not rows[0].decorator_list, 'capture_frozen_smoke_acceptance')
        definitions.append(rows[0])
    original = copy.deepcopy(definitions[0])
    definitions[0].name = 'ORIGINAL_ACCEPTED'
    final_origin = copy.deepcopy(definitions[0])
    definitions[0].name = 'accepted'
    need(shape(definitions[0]) == shape(original), 'capture_smoke_acceptance_name_ast_inverse')
    namespace = types.ModuleType('fixed_freezer_original_smoke_acceptance')
    namespace.__dict__.update(driver.__dict__)
    namespace.FILECENTER_FIELDS = FILECENTER_FIELDS
    exec(compile(ast.fix_missing_locations(ast.Module(body=[final_origin], type_ignores=[])),
                 str(BASE / ORIGIN[0]), 'exec'), namespace.__dict__)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[definitions[1]], type_ignores=[])),
                 str(BASE / FILECENTER[0]), 'exec'), namespace.__dict__)
    bools = tuple(key for key in driver.UI_BOOLS if key not in NAVIGATION_BOOLS)
    counts = tuple(key for key in driver.UI_COUNTS if key != 'navigation_display_seconds')
    fields = frozenset(bools + counts + driver.UI_REASONS)
    original_bools = tuple(key for key in bools if key not in FILECENTER_FIELDS)
    expected_success = tuple(key for key in original_bools if key not in ('radio_admission',
        'physical_ui_verified', 'resource_pending', 'auto_receive_action_issued',
        'receive_trial_initial_available', 'receive_trial_claimed',
        'receive_trial_session_attached', 'interactive_window_expired'))
    need(len(fields) == 46 and fields == driver.UI_FIELDS - frozenset(
         NAVIGATION_BOOLS + ('navigation_display_seconds',)) and driver.UI_SUCCESS == expected_success and
         namespace.ORIGINAL_ACCEPTED.__globals__ is namespace.__dict__ and
         namespace.accepted.__globals__ is namespace.__dict__, 'capture_natural_smoke46')
    names = ('UI_BOOLS', 'UI_COUNTS', 'UI_FIELDS', 'accepted')
    before = tuple(driver.__dict__[name] for name in names)
    after = (bools, counts, fields, namespace.accepted)
    for name, value in zip(names, after):
        driver.__dict__[name] = value
    for name, value in zip(names, before):
        driver.__dict__[name] = value
    need(all(driver.__dict__[name] is value for name, value in zip(names, before)),
         'capture_parser_acceptance_binding_complete_inverse')
    for name, value in zip(names, after):
        driver.__dict__[name] = value
    FACTS.update(capture_original_navigation_public_fields=51, capture_natural_public_fields=46,
        capture_navigation_fields_synthesized=False, capture_parser_binding_complete_inverse_verified=True,
        capture_original_smoke_acceptance_definition_exact=True, capture_original_filecenter_acceptance_definition_exact=True,
        capture_original_smoke_success_fields_exact=True, capture_original_filecenter_success_fields=7)


def prepare():
    current = current_pure()
    original_main = current.main_overlay
    current.main_overlay = lambda tree: capture_main(original_main(tree))
    driver = current.prepare()  # Frozen finite proofs/definitions, never its old main.
    need(driver.main.__globals__ is driver.__dict__ and len(HOST_INPUTS[SELF]) <= 26624,
         'capture_composed_driver_budget')
    watch_overlay(driver.READY_CAPTURE, fixed(current.WORKER))
    original_program = driver.ui_program
    driver.ui_program = lambda inputs, payload, runner, carrier: smoke_program(
        original_program, inputs, payload, runner, carrier, driver.write_new)
    smoke_bindings(driver)
    driver.READ_ME = READ_ME
    FACTS.update(capture_mode='capture-only', capture_stage_entry_available=False,
        capture_freezer_graph_reused=True, capture_old_main_called=False,
        capture_old_full_graph_verifier_called=False, capture_old_suite_called=False,
        capture_startup_seconds=10, capture_owner_seconds=600, capture_cleanup_seconds=60,
        capture_display_seconds=20, capture_ready_seconds=10, capture_outer_seconds=800,
        capture_host_seconds=810, capture_physical_screen_verified=False)
    return driver


def main():
    global SEAL, EVIDENCE, EXTERNAL_EVIDENCE, HOST_OUT
    need(sys.argv[1:] in ([], ['--capture-only']) and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'fixed_pc_modes')
    mode = 'capture-only' if sys.argv[1:] else 'source'
    HOST_OUT = BASE / 'results' / ('receive-proc-freezer-v1-capture-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    HOST_OUT.mkdir(parents=True, exist_ok=False)
    sealer_raw = (BASE / SEALER[0]).read_bytes()
    need((len(sealer_raw), digest(sealer_raw)) == SEALER[1:], 'fixed_sealer_pin')
    SEAL = types.ModuleType('fixed_freezer_capture_sealer')
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
    return driver.main()  # Newly composed original carrier/finally/capture/stock/seal.


if __name__ == '__main__':
    raise SystemExit(main())
