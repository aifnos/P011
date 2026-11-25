"""Fixed current-UI carrier plus one passive after-return workload record.

Default SOURCE or explicit navigation-test only. No runtime75, Runner, Factory,
GUI, stage entry, admission, deadline, original result or PASS gate is changed.
Frozen current pure prepare composes the original algorithms, never old main.
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
SELF = 'host/device_receive_startup_workload_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_STARTUP_WORKLOAD_V1_SOURCE_CHECK.cmd',
        'TEST_MTA_RECEIVE_STARTUP_WORKLOAD_V1_NAVIGATION.cmd')
WINDOW_UI = ('host/device_receive_window_clock_ui_v1_check.py', 18333,
             'd00d179af0286daad48b32e783d031882d7b8be4bd0335b9152e000457ba928a')
OLD_WORKER = ('candidate/receive-window-clock-ui-v1/runtime/ui_session.py', 95350,
              'ed08e5fa40f44170e9d5e7c64c3944e23ab91e3eb17472e4cb8e7f4a5fa9d997')
PREFIX = 'candidate/receive-startup-workload-v1/'
WORKER = (PREFIX + 'runtime/ui_session.py', 95351,
          '8a90425b76303ae28fbd44760bd1f6623980fbf616f25bcfd67953603d275773')
GENERATOR = (PREFIX + 'generate.py', 4290,
             '9d08ab923e7ddc1930aa7305b0b7bd62ea395d5ad554bb03e58fbe9633fed27c')
DELTA = (PREFIX + 'exactsource-delta.json', 1221,
         '4a03e840d604e60b17cded1dca50c5ac936dcb8bf2c7079e7665b384cc5b781c')
GENERATION = (PREFIX + 'generation.json', 1153,
              'b34e2871150ca849190af252605ba8395b00bd5b833c72cbd03863000485ed29')
PROJECTION = (PREFIX + 'workload_projection.py', 6080,
              'acd0a3152e6a78aea488e49253b17cdd3549b8cd9c80bde23ca88bcc1124250b')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
EDITS = (
    dict(name='exclusive_control_suffix', count=1,
         before="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-receive-window-clock-ui-v1'\n",
         after="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-receive-startup-workload-v1'\n"),)
GUARDS = dict(business_bytes_unchanged=True, runtime75_modified=False,
              gui_rebuilt=False, gui_staged=False, public_fields=51,
              startup_seconds=10, service_seconds=600, cleanup_seconds=60,
              device_executed=False, tests_executed=False)
OLD_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-receive-window-clock-ui-v1'"
NEW_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-receive-startup-workload-v1'"
READ_ME = (b'Current frozen window-UI carrier; SOURCE or explicit navigation-test only, never stage.\n'
           b'Worker only changes its exclusive CONTROL suffix; all business definitions/lines remain exact.\n'
           b'One private workload function runs only after original run_fixed has returned and closed.\n'
           b'Group order private35/private_wpa/proc_comm/profile_other; columns attempts/raw_rows/retained_raw_bytes/no_raw_rows.\n'
           b'Raw lengths are retained logical bytes, not verified-complete IO, physical memory, timings or syscall counts.\n'
           b'No incoming/parts reconstruction; no_raw rows stay missing and no paths/PIDs/error text are output.\n'
           b'Discovery columns total/unskipped/nonroot/disappeared/stat_returned/error_present, or None when not retained.\n'
           b'Unknown workload does not modify original public51 facts, strict PASS, failures, closure or admission.\n'
           b'No extra clock, reread, guard/callback, RF action, GUI rebuild/restage or runtime75/Factory/Runner edit.\n'
           b'Original10s prepare/600+60, navigation20, READY10, capture, cancellation and close gates remain strict.\n'
           b'Complete base/new carrier inverse and exact input/raw records stay private before metadata-only publication.\n'
           b'SOURCE is not P011/physical UI/phone/RF or restoration acceptance; workload is not CPU attribution.\n')
HOST_INPUTS = {}
EXTERNAL_INPUTS = {}
FACTS = {}
SEAL = EVIDENCE = EXTERNAL_EVIDENCE = HOST_OUT = None


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(pin):
    return EVIDENCE.read(BASE / pin[0], key=pin[0], pin=pin[1:])


def current_pure():
    raw = fixed(WINDOW_UI)
    nodes = [row for row in ast.parse(raw, feature_version=(3, 5)).body
             if isinstance(row, (ast.Import, ast.ImportFrom, ast.Assign)) or
             isinstance(row, (ast.FunctionDef, ast.ClassDef)) and row.name != 'main']
    need(all(not row.decorator_list for row in nodes if isinstance(row, (ast.FunctionDef, ast.ClassDef))),
         'pure_definition_shape')
    value = types.ModuleType('fixed_startup_workload_current_ui_pure')
    value.__file__ = str(BASE / WINDOW_UI[0])
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                 value.__file__, 'exec'), value.__dict__)
    need('main' not in value.__dict__ and value.WORKER == OLD_WORKER and value.SEALER == SEALER,
         'current_pure_identity')
    return value


def verify_workload(current):
    for pin in (OLD_WORKER, WORKER, GENERATOR, DELTA, GENERATION, PROJECTION):
        fixed(pin)
    spec = json.loads(HOST_INPUTS[DELTA[0]].decode('ascii'))
    need(spec == dict(schema='p011-receive-startup-workload-v1-worker-delta',
        evidence='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=list(GENERATOR),
        source=list(OLD_WORKER), candidate=list(WORKER), replacements=list(EDITS), guards=GUARDS),
        'workload_delta_identity')
    old, new = HOST_INPUTS[OLD_WORKER[0]], HOST_INPUTS[WORKER[0]]
    before, after = (EDITS[0][key].encode('ascii') for key in ('before', 'after'))
    need(old.count(before) == new.count(after) == 1 and old.replace(before, after, 1) == new and
         new.replace(after, before, 1) == old and current.definitions_bytes(old) == current.definitions_bytes(new) and
         len(old.splitlines()) == len(new.splitlines()), 'workload_worker_complete_inverse')
    generator = ast.parse(HOST_INPUTS[GENERATOR[0]], feature_version=(3, 5))
    values = [row.value for row in generator.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
              isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'EDITS']
    need(len(values) == 1 and isinstance(values[0], ast.Tuple) and len(values[0].elts) == 1,
         'generator_edit_shape')
    item = values[0].elts[0]
    need(isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and item.func.id == 'dict' and
         not item.args and tuple(row.arg for row in item.keywords) == ('name', 'count', 'before', 'after') and
         {row.arg: ast.literal_eval(row.value) for row in item.keywords} == EDITS[0], 'generator_edit_identity')
    projection_tree = ast.parse(HOST_INPUTS[PROJECTION[0]], feature_version=(3, 5))
    need(len(projection_tree.body) == 2 and isinstance(projection_tree.body[0], ast.Expr) and
         isinstance(projection_tree.body[1], ast.Assign), 'projection_literal_shape')
    assignment = projection_tree.body[1]
    call = assignment.value
    need(len(assignment.targets) == 1 and isinstance(assignment.targets[0], ast.Name) and
         assignment.targets[0].id == 'TARGET_FRAGMENT' and isinstance(call, ast.Call) and
         isinstance(call.func, ast.Attribute) and call.func.attr == 'encode' and not call.keywords and
         len(call.args) == 1 and ast.literal_eval(call.args[0]) == 'ascii', 'projection_ascii_literal')
    fragment = ast.literal_eval(call.func.value).encode('ascii')
    tree = ast.parse(fragment, feature_version=(3, 5))
    need(0 < len(fragment) <= 8192 and len(tree.body) == 2 and isinstance(tree.body[0], ast.FunctionDef) and
         tree.body[0].name == '_receive_startup_workload_projection_v1' and not tree.body[0].decorator_list and
         current.shape(tree.body[1]) == current.shape(ast.parse('_receive_startup_workload_projection_v1(worker)').body[0]),
         'single_after_return_function')
    FACTS.update(workload_worker_complete_inverse_verified=True, workload_business_bytes_unchanged=True,
        workload_function_bytes=len(fragment), workload_function_sha256=digest(fragment),
        workload_row_cap=512, workload_discovery_cap=4096, workload_after_return_only=True,
        workload_public_fields_added=0, workload_new_clock=False, workload_resource_io=False,
        workload_guard_called=False, workload_cpu_attribution=False)
    return fragment


def main_overlay(current, tree):
    before = copy.deepcopy(tree)
    controls = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and len(row.targets) == 1 and
                isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'control']
    need(len(controls) == 1 and current.shape(controls[0].value) == current.shape(current.expression(OLD_CONTROL)),
         'workload_control_shape')
    original = controls[0].value
    controls[0].value = current.expression(NEW_CONTROL)
    final = copy.deepcopy(tree)
    controls[0].value = original
    need(current.shape(tree) == current.shape(before), 'workload_main_complete_inverse')
    FACTS['workload_main_complete_inverse_verified'] = True
    return ast.fix_missing_locations(final)


def program_overlay(current, original, inputs, payload, runner, carrier, fragment, fresh):
    raw, wire = original(inputs, payload, runner, carrier)
    old = current.source_block('worker', OLD_WORKER, inputs[OLD_WORKER[0]], carrier)
    new = current.source_block('worker', WORKER, inputs[WORKER[0]], carrier)
    anchor = b'print("RESULT="+repr(component));print("MTA_REMOTE_OK")\n'
    edits = ((old, new), (anchor, fragment + anchor))
    value = raw
    for before, after in edits:
        need(value.count(before) == 1, 'workload_carrier_anchor')
        value = value.replace(before, after, 1)
    inverse = value
    for before, after in reversed(edits):
        need(inverse.count(after) == 1, 'workload_carrier_inverse_count')
        inverse = inverse.replace(after, before, 1)
    need(inverse == raw and len(value) <= 2097152 and max(map(len, value.splitlines())) <= 2048 and
         len(wire) <= 6291456, 'workload_carrier_complete_inverse_budget')
    # The same unique original call remains before every new function byte.
    returned = b'component=worker.run_fixed(sources["runner"],tuple(artifacts),sources["assets"],navigation_test=True,filecenter_sources=tuple(fc))\n'
    need(value.count(returned) == 1 and value.index(returned) + len(returned) < value.index(fragment) and
         value.count(fragment) == 1, 'workload_after_return_order')
    ast.parse(value, feature_version=(3, 5))
    fresh(HOST_OUT / 'private-current-window-ui-bootstrap.py', raw)
    fresh(HOST_OUT / 'private-current-window-ui-wire.raw', wire)
    FACTS.update(workload_carrier_complete_inverse_verified=True,
        workload_program_bytes=len(value), workload_program_max_line=max(map(len, value.splitlines())))
    return value, wire


def prepare():
    current = current_pure()
    fragment = verify_workload(current)
    for name in ('HOST_INPUTS', 'EXTERNAL_INPUTS', 'FACTS', 'SEAL', 'EVIDENCE', 'EXTERNAL_EVIDENCE', 'HOST_OUT', 'READ_ME'):
        current.__dict__[name] = globals()[name]
    original_main = current.composed_main
    current.composed_main = lambda original, raw: main_overlay(current, original_main(original, raw))
    driver = current.prepare()  # Frozen pure composition; no archived main or device call.
    need(len(driver.UI_FIELDS) == 51 and len(HOST_INPUTS[SELF]) <= 26624, 'original_schema_host_budget')
    original_program = driver.ui_program
    driver.ui_program = lambda inputs, payload, runner, carrier: program_overlay(
        current, original_program, inputs, payload, runner, carrier, fragment, driver.write_new)
    return driver


def main():
    global SEAL, EVIDENCE, EXTERNAL_EVIDENCE, HOST_OUT
    need(sys.argv[1:] in ([], ['--navigation-test']) and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'fixed_pc_modes')
    HOST_OUT = BASE / 'results' / ('receive-startup-workload-v1-' +
        ('navigation-test-' if sys.argv[1:] else 'source-') +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    HOST_OUT.mkdir(parents=True, exist_ok=False)
    sealer_raw = (BASE / SEALER[0]).read_bytes()
    need((len(sealer_raw), digest(sealer_raw)) == SEALER[1:], 'fixed_sealer_pin')
    SEAL = types.ModuleType('fixed_startup_workload_sealer')
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
        report = dict(passed=False, mode='navigation-test' if sys.argv[1:] else 'source',
            source_checked=False, source_preserved=False, error_kind=type(error).__name__,
            device_invoked=False, device_execution_unknown=False, phone_tested=False,
            restoration_verified=False, old_graphs=0, old_suites=0, old_builders=0,
            checker_exit=1, integration_facts=dict(FACTS), historical_main_called=False,
            input_pins=[dict(path=name, bytes=len(raw), sha256=digest(raw), complete=name not in EVIDENCE.partial)
                        for name, raw in HOST_INPUTS.items()])
        sealed = SEAL.seal_result(HOST_OUT, report, READ_ME)
        print(json.dumps(dict(passed=False, mode=report['mode'], error_kind=report['error_kind'],
            result_dir=str(HOST_OUT), public_result_zip=str(sealed['archive']) if sealed['archive'] else None,
            zip_sha256=sealed['archive_sha256']), sort_keys=True))
        return sealed['host_exit']
    return driver.main()  # Newly composed main owns original finally/capture/strict PASS/seal.


if __name__ == '__main__':
    raise SystemExit(main())
