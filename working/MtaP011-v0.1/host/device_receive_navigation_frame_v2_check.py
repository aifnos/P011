"""Fixed current carrier with one cached-refusal frame rebind and new CONTROL.

SOURCE by default, explicit navigation-test only. Frozen pure prepare composes
the original finally/51-field PASS/capture chain; no old main, suite or staging.
Worker definitions/lines and all radio/admission/navigation business stay exact.
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
SELF = 'host/device_receive_navigation_frame_v2_check.py'
CMDS = ('HOST_MTA_RECEIVE_NAVIGATION_FRAME_V2_SOURCE_CHECK.cmd',
        'TEST_MTA_RECEIVE_NAVIGATION_FRAME_V2.cmd')
CURRENT = ('host/device_receive_startup_workload_v1_check.py', 14344,
           'bd195e52e7c3027078b9bcf887ab7a745d962a42aa39153123bb7957d6a0b15a')
SOURCE = ('candidate/receive-startup-workload-v1/runtime/ui_session.py', 95351,
          '8a90425b76303ae28fbd44760bd1f6623980fbf616f25bcfd67953603d275773')
PREFIX = 'candidate/receive-navigation-frame-v2/'
WORKER = (PREFIX + 'runtime/ui_session.py', 95351,
          '0c53b23051e5d79cdc392b2f89d3d21de2425028ff4f76292284a72f631cb4fe')
GENERATOR = (PREFIX + 'generate.py', 3736,
             '9b2ab1e766ba5fb4d33506a827235d184cf2eb199f0ba9eca48f5badbe313826')
DELTA = (PREFIX + 'exactsource-delta.json', 1266,
         'ad9521a9d60a7cd9fe85e6837f0c6579473b6bbd8a47e9dcde294d9ed40ff547')
REFUSAL = ('host/receive_navigation_refusal_projection_v1.py', 7474,
           'c48192bd978e0bb056f5ea0c74617628b6d9e27936ca9e5697310e39b7bb1bb4')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
EDITS = (
    dict(name='exclusive_control_suffix', count=1,
         before="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-receive-startup-workload-v1'\n",
         after="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-receive-navigation-frame-v2'\n"),)
GUARDS = dict(business_bytes_unchanged=True, worker_line_numbers_unchanged=True,
              runtime75_modified=False, gui_rebuilt=False, gui_staged=False,
              public_fields=51, startup_seconds=10, service_seconds=600,
              cleanup_seconds=60, device_executed=False, tests_executed=False)
OLD_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-receive-startup-workload-v1'"
NEW_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-receive-navigation-frame-v2'"
READ_ME = (b'Fixed current startup-workload carrier; default SOURCE or explicit navigation-test only.\n'
           b'Worker changes only exclusive CONTROL suffix; all definition bytes and line numbers stay exact.\n'
           b'Existing cached refusal helper binds actual run_fixed traceback line1560 instead of1557.\n'
           b'Its existing Runner817, namespace/code/frame/type guards and limits64 remain exact.\n'
           b'No guard re-evaluation, extra clock, read, callback, cancellation or radio action is added.\n'
           b'Trial/cancelled/idle cached observations remain separate observations, not an atomic receipt.\n'
           b'Original public51/PASS/failures/finally/capture and10/600+60/20/READY10 caps stay strict.\n'
           b'GUI20/runtime75/Factory/Runner/staged assets and all historical results stay unchanged.\n'
           b'Complete original/new carrier byte/AST inverse and private inputs/raw remain retained.\n'
           b'SOURCE is not P011 UI, phone, RF, receive admission or full restoration acceptance.\n')
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
    value = types.ModuleType('fixed_navigation_frame_v2_current_pure')
    value.__file__ = str(BASE / CURRENT[0])
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                 value.__file__, 'exec'), value.__dict__)
    need('main' not in value.__dict__ and value.WORKER == SOURCE and value.SEALER == SEALER,
         'current_pure_identity')
    for name in ('HOST_INPUTS', 'EXTERNAL_INPUTS', 'FACTS', 'SEAL', 'EVIDENCE',
                 'EXTERNAL_EVIDENCE', 'HOST_OUT', 'READ_ME'):
        value.__dict__[name] = globals()[name]
    return value


def verify_worker():
    for pin in (SOURCE, WORKER, GENERATOR, DELTA):
        fixed(pin)
    need(json.loads(HOST_INPUTS[DELTA[0]].decode('ascii')) == dict(
        schema='p011-receive-navigation-frame-v2-worker-delta',
        evidence='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=list(GENERATOR),
        source=list(SOURCE), candidate=list(WORKER), replacements=list(EDITS), guards=GUARDS),
        'worker_delta_identity')
    old, new = HOST_INPUTS[SOURCE[0]], HOST_INPUTS[WORKER[0]]
    before, after = (EDITS[0][key].encode('ascii') for key in ('before', 'after'))
    need(old.count(before) == new.count(after) == 1 and old.replace(before, after, 1) == new and
         new.replace(after, before, 1) == old and len(old.splitlines()) == len(new.splitlines()),
         'worker_complete_byte_inverse')
    def definitions(raw):
        lines = raw.splitlines(keepends=True)
        return [(row.name, row.lineno, row.end_lineno, b''.join(lines[row.lineno - 1:row.end_lineno]))
                for row in ast.parse(raw, feature_version=(3, 5)).body
                if isinstance(row, (ast.FunctionDef, ast.ClassDef))]
    need(definitions(old) == definitions(new) and
         shape(ast.parse(new.replace(after, before, 1), feature_version=(3, 5))) ==
         shape(ast.parse(old, feature_version=(3, 5))), 'worker_definition_ast_inverse')
    FACTS.update(navigation_frame_worker_complete_inverse_verified=True,
        navigation_frame_worker_definition_bytes_unchanged=True,
        navigation_frame_worker_line_numbers_unchanged=True, navigation_frame_worker_pin=list(WORKER))


def main_overlay(tree):
    original = copy.deepcopy(tree)
    controls = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and len(row.targets) == 1 and
                isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'control']
    need(len(controls) == 1 and shape(controls[0].value) == shape(ast.parse(OLD_CONTROL, mode='eval').body),
         'control_shape')
    old = controls[0].value
    controls[0].value = ast.parse(NEW_CONTROL, mode='eval').body
    final = copy.deepcopy(tree)
    controls[0].value = old
    need(shape(tree) == shape(original), 'main_complete_ast_inverse')
    FACTS['navigation_frame_main_complete_ast_inverse_verified'] = True
    return ast.fix_missing_locations(final)


def refusal_fragments():
    tree = ast.parse(fixed(REFUSAL), feature_version=(3, 5))
    rows = [row.value for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
            isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'TARGET_FRAGMENT']
    need(len(rows) == 1, 'refusal_literal_shape')
    raw = ast.literal_eval(rows[0])
    need(type(raw) is bytes and 0 < len(raw) <= 8192 and
         raw.count(b'code.co_firstlineno!=816') == 1, 'frozen_refusal_literal')
    # Runner817 is already present in the complete frozen current carrier.
    old = raw.replace(b'code.co_firstlineno!=816', b'code.co_firstlineno!=817', 1)
    before, after = b'tb.tb_lineno!=1557', b'tb.tb_lineno!=1560'
    need(old.count(before) == 1, 'refusal_frame_byte_count')
    new = old.replace(before, after, 1)
    original = ast.parse(old, feature_version=(3, 5))
    forward = copy.deepcopy(original)
    comparisons = [row for row in ast.walk(forward) if isinstance(row, ast.Compare) and
        shape(row.left) == shape(ast.parse('tb.tb_lineno', mode='eval').body) and
        len(row.ops) == len(row.comparators) == 1 and isinstance(row.ops[0], ast.NotEq) and
        isinstance(row.comparators[0], ast.Constant) and row.comparators[0].value == 1557]
    need(len(comparisons) == 1, 'refusal_frame_ast_count')
    comparisons[0].comparators[0].value = 1560
    need(shape(forward) == shape(ast.parse(new, feature_version=(3, 5))), 'refusal_frame_ast_forward')
    comparisons[0].comparators[0].value = 1557
    need(new.count(after) == 1 and new.replace(after, before, 1) == old and
         shape(forward) == shape(original), 'refusal_frame_complete_inverse')
    FACTS.update(navigation_frame_refusal_line_rebound=1560, navigation_frame_runner_line_retained=817,
        navigation_frame_refusal_complete_inverse_verified=True, navigation_frame_cached_data_only=True,
        navigation_frame_traceback_limit=64, navigation_frame_failure_limit=64)
    return old, new


def overlay_program(original, inputs, payload, runner, carrier, fragments, fresh):
    raw, wire = original(inputs, payload, runner, carrier)
    def block(pin):
        return ("sources['worker']=decode((\n" + carrier.encoded(inputs[pin[0]]) +
                '),' + repr(pin[1]) + ',' + repr(pin[2]) + ')').encode('ascii')
    edits = ((block(SOURCE), block(WORKER)), fragments)
    new = raw
    for before, after in edits:
        need(new.count(before) == 1, 'carrier_overlay_count')
        new = new.replace(before, after, 1)
    inverse = new
    for before, after in reversed(edits):
        need(inverse.count(after) == 1, 'carrier_inverse_count')
        inverse = inverse.replace(after, before, 1)
    need(inverse == raw and shape(ast.parse(inverse, feature_version=(3, 5))) ==
         shape(ast.parse(raw, feature_version=(3, 5))) and len(new) <= 2097152 and
         max(map(len, new.splitlines())) <= 2048 and len(wire) <= 6291456,
         'carrier_complete_byte_ast_inverse_budget')
    ast.parse(new, feature_version=(3, 5))
    fresh(HOST_OUT / 'private-current-startup-workload-bootstrap.py', raw)
    fresh(HOST_OUT / 'private-current-startup-workload-wire.raw', wire)
    FACTS.update(navigation_frame_carrier_complete_byte_ast_inverse_verified=True,
        navigation_frame_program_bytes=len(new), navigation_frame_program_max_line=max(map(len, new.splitlines())))
    return new, wire


def prepare():
    current = current_pure()
    verify_worker()
    fragments = refusal_fragments()
    original_main = current.main_overlay
    current.main_overlay = lambda window, tree: main_overlay(original_main(window, tree))
    driver = current.prepare()  # Frozen definitions only; archived main is absent.
    need(len(driver.UI_FIELDS) == 51 and len(HOST_INPUTS[SELF]) <= 26624, 'original_schema_host_budget')
    original_program = driver.ui_program
    driver.ui_program = lambda inputs, payload, runner, carrier: overlay_program(
        original_program, inputs, payload, runner, carrier, fragments, driver.write_new)
    return driver


def main():
    global SEAL, EVIDENCE, EXTERNAL_EVIDENCE, HOST_OUT
    need(sys.argv[1:] in ([], ['--navigation-test']) and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'fixed_pc_modes')
    mode = 'navigation-test' if sys.argv[1:] else 'source'
    HOST_OUT = BASE / 'results' / ('receive-navigation-frame-v2-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    HOST_OUT.mkdir(parents=True, exist_ok=False)
    sealer_raw = (BASE / SEALER[0]).read_bytes()
    need((len(sealer_raw), digest(sealer_raw)) == SEALER[1:], 'fixed_sealer_pin')
    SEAL = types.ModuleType('fixed_navigation_frame_v2_sealer')
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
    return driver.main()  # Newly composed main retains original finally/capture/PASS/seal.


if __name__ == '__main__':
    raise SystemExit(main())
