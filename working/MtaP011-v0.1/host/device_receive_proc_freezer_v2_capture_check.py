"""Capture-only v2: existing20s smoke with an exclusive CONTROL suffix.

SOURCE by default; explicit --capture-only reuses frozen v1 pure prepare.
Only an in-memory Worker CONTROL_NAME line and HOST/WATCH directory binding
change. Old sources/control directories/logs remain untouched. The original
46-field smoke/capture/stock/finally/resource-close gates stay strict.
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
SELF = 'host/device_receive_proc_freezer_v2_capture_check.py'
CMDS = ('HOST_MTA_RECEIVE_PROC_FREEZER_V2_CAPTURE_SOURCE_CHECK.cmd',
        'TEST_MTA_RECEIVE_PROC_FREEZER_V2_CAPTURE.cmd')
CURRENT = ('host/device_receive_proc_freezer_v1_capture_check.py', 22894,
           'a79a5fea72c4693c9d2c2bf1fce853d7ae272e6776684659ce410690160ab0c4')
WORKER = ('candidate/receive-proc-freezer-v1/runtime/ui_session.py', 100157,
          '06196ee0567dd5e3076638a3821974985e5b771497922eb0ee7ecdf916ab0697')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
SESSION = '559c72ccf8f8ff1b7fc83fb6'
OLD_SUFFIX = '-receive-proc-freezer-v1'
NEW_SUFFIX = '-receive-proc-freezer-capture-v2'
OLD_NAME = "'p011-mta-ui-session-' + SESSION + " + repr(OLD_SUFFIX)
NEW_NAME = "'p011-mta-ui-session-' + SESSION + " + repr(NEW_SUFFIX)
OLD_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + " + repr(OLD_SUFFIX)
NEW_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + " + repr(NEW_SUFFIX)
OLD_ROOT = '/var/volatile/tmp/p011-mta-ui-session-' + SESSION + OLD_SUFFIX
NEW_ROOT = '/var/volatile/tmp/p011-mta-ui-session-' + SESSION + NEW_SUFFIX
READ_ME = (b'Independent capture-v2 SOURCE or explicit capture-only existing20-second smoke profile.\n'
           b'Frozen capture-v1 pure definitions/proofs supply one carrier; no old main/SOURCE/test/suite/build runs.\n'
           b'Old navigation/capture-v1 history and old retained CONTROL directories/logs are never changed/deleted/archived.\n'
           b'Actual fixed Worker input remains unchanged; derive only its complete CONTROL_NAME assignment line in memory.\n'
           b'Derived Worker actual bytes/hash are computed now, privately preserved and bound in its one encoded decoder block.\n'
           b'Complete Worker/target byte+AST inverse preserves every business definition byte and original line number.\n'
           b'HOST log-pull control and WATCH complete root line synchronize the exclusive capture-v2 suffix.\n'
           b'Worker CONTROL is derived by its original expression; guardian still binds actual new-directory metadata.\n'
           b'Original exclusive os.mkdir is retained: an existing new CONTROL refuses, never reuses or removes old data.\n'
           b'Root operator must verify the new CONTROL is absent before device launch; SOURCE cannot prove current absence.\n'
           b'Flat graph keeps its fixed original Worker pin; no derived future pin/asset is written into graph or runtime75.\n'
           b'Natural46/strict original smoke+FC7/capture.complete/stock/finally/PID-start/FD/inode/READY/DRM stay unchanged.\n'
           b'No QtTest navigation, receive cancellation, file-page action, automatic RF or phone/transfer action.\n'
           b'GUI20/runtime75/FC9/Runner/Validator/session/candidate exe are reused exact, never rebuilt or restaged.\n'
           b'Original startup10/600+60/display20/READY10/outer800/HOST810/2MiB/line2048/wire6MiB/HOST26KiB stay.\n'
           b'Raw sources/streams/exits/derived Worker/WATCH/images precede metadata-only publication in private evidence.\n'
           b'SOURCE is not device output; capture is not navigation/touch/phone/RF/full wireless restoration acceptance.\n')
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
    value = types.ModuleType('fixed_freezer_capture_v2_capture_v1_pure')
    value.__file__ = str(BASE / CURRENT[0])
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                 value.__file__, 'exec'), value.__dict__)
    need('main' not in value.__dict__ and value.SELF == CURRENT[0] and value.SESSION == SESSION and
         value.WATCH_ROOT == OLD_ROOT and value.SEALER == SEALER, 'capture_v2_pure_identity')
    for name in ('HOST_INPUTS', 'EXTERNAL_INPUTS', 'FACTS', 'SEAL', 'EVIDENCE',
                 'EXTERNAL_EVIDENCE', 'HOST_OUT', 'READ_ME'):
        value.__dict__[name] = globals()[name]
    return value


def control_main(tree):
    """Only the final HOST's control-directory expression, full AST inverse."""
    before = copy.deepcopy(tree)
    rows = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and len(row.targets) == 1 and
            isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'control']
    need(len(rows) == 1 and shape(rows[0].value) == shape(expression(OLD_CONTROL)),
         'capture_v2_original_host_control')
    original = rows[0].value
    rows[0].value = expression(NEW_CONTROL)
    final = copy.deepcopy(tree)
    rows[0].value = original
    need(shape(tree) == shape(before), 'capture_v2_host_complete_ast_inverse')
    FACTS['capture_v2_host_control_complete_ast_inverse_verified'] = True
    return ast.fix_missing_locations(final)


def definitions(raw):
    lines = raw.splitlines(keepends=True)
    return [(row.name, row.lineno, row.end_lineno, b''.join(lines[row.lineno - 1:row.end_lineno]))
            for row in ast.parse(raw, feature_version=(3, 5)).body
            if isinstance(row, (ast.FunctionDef, ast.ClassDef))]


def derived_worker():
    old = fixed(WORKER)
    line = ('CONTROL_NAME = ' + OLD_NAME).encode('ascii')
    choices = [row for row in (line + b'\n', line + b'\r\n') if old.count(row) == 1]
    need(len(choices) == 1, 'capture_v2_worker_complete_line_count')
    before = choices[0]
    after = before.replace(OLD_SUFFIX.encode('ascii'), NEW_SUFFIX.encode('ascii'), 1)
    new = old.replace(before, after, 1)
    need(new.count(after) == 1 and new.replace(after, before, 1) == old and
         len(new.splitlines()) == len(old.splitlines()), 'capture_v2_worker_complete_byte_inverse')
    tree = ast.parse(old, feature_version=(3, 5))
    original = copy.deepcopy(tree)
    rows = [row for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
            isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'CONTROL_NAME']
    controls = [row for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
                isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'CONTROL']
    need(len(rows) == len(controls) == 1 and shape(rows[0].value) == shape(expression(OLD_NAME)) and
         shape(controls[0].value) == shape(expression("'/var/volatile/tmp/' + CONTROL_NAME")),
         'capture_v2_original_worker_control_ast')
    previous = rows[0].value
    rows[0].value = expression(NEW_NAME)
    need(shape(tree) == shape(ast.parse(new, feature_version=(3, 5))), 'capture_v2_worker_complete_ast_forward')
    rows[0].value = previous
    need(shape(tree) == shape(original) and shape(ast.parse(new.replace(after, before, 1),
         feature_version=(3, 5))) == shape(original) and definitions(old) == definitions(new),
         'capture_v2_worker_complete_ast_inverse_definitions_lines')
    pin = (len(new), digest(new))
    SEAL.fresh(HOST_OUT / 'private-derived-freezer-capture-v2-worker.py', new)
    FACTS.update(capture_v2_source_worker_pin=list(WORKER), capture_v2_derived_worker_pin=list(pin),
        capture_v2_worker_complete_byte_ast_inverse_verified=True,
        capture_v2_worker_all_definitions_bytes_lines_unchanged=True,
        capture_v2_worker_delta='one_complete_CONTROL_NAME_assignment_line',
        capture_actual_worker_modified=True, capture_base_worker_file_modified=False,
        capture_runtime75_modified=False, capture_v2_graph_worker_pin_unchanged=True)
    return new, pin


def watch_control(capture):
    old = capture.watch.encode('ascii')
    before = ('root=' + repr(OLD_ROOT) + '\n').encode('ascii')
    after = ('root=' + repr(NEW_ROOT) + '\n').encode('ascii')
    need(old.count(before) == 1 and old.count(after) == 0, 'capture_v2_watch_original_root_line')
    new = old.replace(before, after, 1)
    need(new.count(after) == 1 and new.replace(after, before, 1) == old and
         len(new.splitlines()) == len(old.splitlines()) and len(new) <= 4096 and
         max(map(len, new.splitlines())) <= 2048, 'capture_v2_watch_complete_byte_inverse_budget')
    tree = ast.parse(old, feature_version=(3, 5))
    original = copy.deepcopy(tree)
    rows = [row for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
            isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'root']
    need(len(rows) == 1 and ast.literal_eval(rows[0].value) == OLD_ROOT, 'capture_v2_watch_root_ast')
    rows[0].value = ast.Constant(value=NEW_ROOT)
    need(shape(tree) == shape(ast.parse(new, feature_version=(3, 5))), 'capture_v2_watch_complete_ast_forward')
    rows[0].value = ast.Constant(value=OLD_ROOT)
    need(shape(tree) == shape(original) and shape(ast.parse(new.replace(after, before, 1),
         feature_version=(3, 5))) == shape(original) and definitions(old) == definitions(new),
         'capture_v2_watch_complete_ast_inverse_definitions_lines')
    SEAL.fresh(HOST_OUT / 'private-freezer-capture-v2-watch.py', new)
    capture.watch = new.decode('ascii')
    FACTS.update(capture_v2_watch_complete_byte_ast_inverse_verified=True,
        capture_v2_watch_original_pin=[len(old), digest(old)],
        capture_watch_root=NEW_ROOT, capture_watch_actual_pin=[len(new), digest(new)],
        capture_v2_watch_guard_candidate_bytes_lines_unchanged=True,
        capture_v2_exclusive_control_name=True, capture_v2_control_absence_device_observed=False)


def worker_program(original, inputs, payload, runner, carrier, value, fresh):
    raw, wire = original(inputs, payload, runner, carrier)
    worker, pin = value
    def block(source, source_pin):
        return ("sources['worker']=decode((\n" + carrier.encoded(source) +
                '),' + repr(source_pin[0]) + ',' + repr(source_pin[1]) + ')').encode('ascii')
    need(inputs[WORKER[0]] == fixed(WORKER), 'capture_v2_original_worker_input_binding')
    before, after = block(inputs[WORKER[0]], WORKER[1:]), block(worker, pin)
    need(raw.count(before) == 1 and raw.count(after) == 0, 'capture_v2_encoded_worker_unique')
    new = raw.replace(before, after, 1)
    need(new.count(after) == 1 and new.replace(after, before, 1) == raw and
         len(new) <= 2097152 and max(map(len, new.splitlines())) <= 2048 and len(wire) <= 6291456,
         'capture_v2_target_complete_byte_inverse_budget')
    tree = ast.parse(raw, feature_version=(3, 5))
    original_tree = copy.deepcopy(tree)
    old_node, new_node = (ast.parse(source, feature_version=(3, 5)).body[0] for source in (before, after))
    positions = [at for at, row in enumerate(tree.body) if shape(row) == shape(old_node)]
    need(len(positions) == 1, 'capture_v2_target_worker_ast_anchor')
    at = positions[0]
    original_node = tree.body[at]
    tree.body[at] = new_node
    need(shape(tree) == shape(ast.parse(new, feature_version=(3, 5))), 'capture_v2_target_complete_ast_forward')
    tree.body[at] = original_node
    need(shape(tree) == shape(original_tree) and shape(ast.parse(new.replace(after, before, 1),
         feature_version=(3, 5))) == shape(original_tree), 'capture_v2_target_complete_ast_inverse')
    fresh(HOST_OUT / 'private-freezer-capture-v1-mother-bootstrap.py', raw)
    FACTS.update(capture_v2_target_complete_byte_ast_inverse_verified=True,
        capture_v2_target_delta='one_actual_derived_worker_encoded_block_with_actual_decoder_pin',
        capture_actual_worker_modified=True, capture_base_worker_file_modified=False,
        capture_v2_program_bytes=len(new), capture_v2_program_max_line=max(map(len, new.splitlines())),
        capture_v2_wire_unchanged=True, capture_v2_wire_bytes=len(wire),
        capture_v2_old_control_deleted=False, capture_v2_old_control_archived=False)
    return new, wire


def prepare():
    current = current_pure()
    original_main = current.capture_main
    current.capture_main = lambda tree: control_main(original_main(tree))
    driver = current.prepare()  # Frozen pure composition only; v1 main is absent.
    need(driver.main.__globals__ is driver.__dict__ and len(driver.UI_FIELDS) == 46 and
         len(HOST_INPUTS[SELF]) <= 26624, 'capture_v2_original_smoke46_host_budget')
    worker = derived_worker()
    watch_control(driver.READY_CAPTURE)
    original_program = driver.ui_program
    driver.ui_program = lambda inputs, payload, runner, carrier: worker_program(
        original_program, inputs, payload, runner, carrier, worker, driver.write_new)
    driver.READ_ME = READ_ME
    FACTS.update(capture_v2_mode='capture-only', capture_v2_source_namespace='receive-proc-freezer-v2-capture',
        capture_v2_existing_smoke46_preserved=True, capture_v2_original_close_gates_preserved=True,
        capture_v2_existing_capture_complete_preserved=True, capture_v2_no_navigation_revalidation=True)
    return driver


def main():
    global SEAL, EVIDENCE, EXTERNAL_EVIDENCE, HOST_OUT
    need(sys.argv[1:] in ([], ['--capture-only']) and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'fixed_pc_modes')
    mode = 'capture-only' if sys.argv[1:] else 'source'
    HOST_OUT = BASE / 'results' / ('receive-proc-freezer-v2-capture-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    HOST_OUT.mkdir(parents=True, exist_ok=False)
    sealer_raw = (BASE / SEALER[0]).read_bytes()
    need((len(sealer_raw), digest(sealer_raw)) == SEALER[1:], 'fixed_sealer_pin')
    SEAL = types.ModuleType('fixed_freezer_capture_v2_sealer')
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
    return driver.main()  # Original strict smoke/capture/finally/stock/seal.


if __name__ == '__main__':
    raise SystemExit(main())
