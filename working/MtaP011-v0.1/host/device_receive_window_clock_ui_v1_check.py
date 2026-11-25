"""Independent fixed-window navigation overlay; no staging entry is exposed.

Default SOURCE or explicit navigation-test only. The frozen durable UI graph
still verifies its original Worker/Runner delta. A separate two-edit window
proof and Worker pin/control proof bind the new stdin carrier; GUI20, runtime75,
FC9, public51, capture, acceptance and original 600+60/20/10 caps stay unchanged.
No historical main, suite, generator, builder, automatic RF or phone runs here.
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
SELF = 'host/device_receive_window_clock_ui_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_WINDOW_CLOCK_UI_V1_SOURCE_CHECK.cmd',
        'TEST_MTA_RECEIVE_WINDOW_CLOCK_UI_V1_NAVIGATION.cmd')
UI_HOST = ('host/device_formal_receive_durable_ui_v1_check.py', 25979,
           'f870215893a5fd9a8317e76f5c5b0d3fa4971269c862d9d1e9f603709b4260dd')
WINDOW_HOST = ('host/device_receive_window_clock_v1_startup_check.py', 20955,
               'df818fcd7e9a28dfb88af123919cdc8fbbefcaaf6b7cfa42d48a68bc250de04d')
OLD_WORKER = ('candidate/formal-receive-durable-ui-v1/runtime/ui_session.py', 95352,
              '7690e2c87f8438c3422986d180381858e7e47588ee60c725c9eb8f73dd628972')
OLD_RUNNER = ('candidate/formal-receive-durable-ui-v1/runtime/mta_formal_receive_session.py',
              88773, 'a5dffa34a9dac7fdcc240dd59e1472448dbe7f076ec5d1240804401cbaa1c0a3')
NEW_RUNNER = ('candidate/receive-window-clock-v1/runtime/mta_formal_receive_navigation_session.py',
              88850, '2aa5c840d9df5293fe10d385060821269d5170da4261b751c49af091ccf31f48')
PREFIX = 'candidate/receive-window-clock-ui-v1/'
WORKER = (PREFIX + 'runtime/ui_session.py', 95350,
          'ed08e5fa40f44170e9d5e7c64c3944e23ab91e3eb17472e4cb8e7f4a5fa9d997')
GENERATOR = (PREFIX + 'generate.py', 5010,
             '7dc84f00ea512e90e5345d616ec3fc0a34453c127646a54a3a881758540de544')
DELTA = (PREFIX + 'exactsource-delta.json', 1723,
         '1e2a753ec48ee77f1a2301c9666159d01ed3885fdef5c4a083e27838631d1fdc')
GENERATION = (PREFIX + 'generation.json', 1389,
              '416fe033efbf56f7bda984a8fa1ace6c874a17ee4869e61d1b2347d5c19c3470')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
EDITS = (
    dict(name='fixed_runner_pin', count=1,
         before="RUNNER_PIN = (88773, 'a5dffa34a9dac7fdcc240dd59e1472448dbe7f076ec5d1240804401cbaa1c0a3')\n",
         after="RUNNER_PIN = (88850, '2aa5c840d9df5293fe10d385060821269d5170da4261b751c49af091ccf31f48')\n"),
    dict(name='exclusive_control_suffix', count=1,
         before="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-receive-durable-ui-v1'\n",
         after="CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-receive-window-clock-ui-v1'\n"))
GUARDS = dict(business_bytes_unchanged=True, gui_rebuilt=False, gui_staged=False,
              runtime75_modified=False, public_fields=51, ready_seconds=10,
              navigation_seconds=20, service_seconds=600, cleanup_seconds=60,
              device_executed=False, tests_executed=False)
OLD_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-durable-ui-v1'"
NEW_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-receive-window-clock-ui-v1'"
READ_ME = (b'Independent window-clock navigation carrier; default SOURCE or explicit navigation-test only.\n'
           b'Actual staged GUI20/session/validator, runtime75 and FC9 are not rebuilt or restaged.\n'
           b'Frozen durable UI graph verifies only its base Worker/Runner/spec; separate new window proof is exact inverse.\n'
           b'Worker only changes fixed RUNNER_PIN and exclusive CONTROL suffix; all business definition bytes stay.\n'
           b'Runner only changes two window_current duration expressions; no epsilon, new clock or renewal.\n'
           b'Original600+60, launched+20, READY10, public51, QtTest and post-READY capture/DRM remain strict.\n'
           b'Original receive request, cancelled/empty predicates, no-auto-RF and complete resource-close gates stay.\n'
           b'Only private refusal diagnostic observer line816 becomes actual817; no public field or admission changes.\n'
           b'Bootstrap2MiB, line2048, wire6MiB, HOST26KiB, outer800 and HOST810 remain bounded.\n'
           b'Base/new carriers, exact inputs, raw failures and images stay private before metadata-only publication.\n'
           b'SOURCE is not P011 runtime or physical UI/phone/RF/full wireless restoration acceptance.\n')
HOST_INPUTS = {}
EXTERNAL_INPUTS = {}
FACTS = {}
UI = SEAL = EVIDENCE = EXTERNAL_EVIDENCE = HOST_OUT = None


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(pin):
    return EVIDENCE.read(BASE / pin[0], key=pin[0], pin=pin[1:])


def pure(pin, names=None):
    """Select imports/constants/pure definitions, never archived main or guard."""
    raw = fixed(pin)
    tree = ast.parse(raw, feature_version=(3, 5))
    nodes = [row for row in tree.body if isinstance(row, (ast.Import, ast.ImportFrom, ast.Assign))]
    functions = [row for row in tree.body if isinstance(row, (ast.FunctionDef, ast.ClassDef)) and
                 row.name != 'main' and (names is None or row.name in names)]
    need(all(not row.decorator_list for row in functions) and
         (names is None or {row.name for row in functions} == set(names)), 'pure_definition_shape')
    scope = types.ModuleType('fixed_window_ui_pure_' + Path(pin[0]).stem)
    scope.__file__ = str(BASE / pin[0])
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes + functions, type_ignores=[])),
                 scope.__file__, 'exec'), scope.__dict__)
    need('main' not in scope.__dict__, 'historical_main_selected')
    return scope


def replay(raw, inverse=False):
    for row in reversed(EDITS) if inverse else EDITS:
        before = row['after' if inverse else 'before'].encode('ascii')
        after = row['before' if inverse else 'after'].encode('ascii')
        need(raw.count(before) == 1, 'worker_overlay_count')
        raw = raw.replace(before, after, 1)
    return raw


def definitions_bytes(raw):
    lines = raw.splitlines(keepends=True)
    return [(node.name, b''.join(lines[node.lineno - 1:node.end_lineno]))
            for node in ast.parse(raw, feature_version=(3, 5)).body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef))]


def verify_overlay():
    # This is the frozen core HOST's finite SOURCE proof, not its main/suite.
    proof = pure(WINDOW_HOST, ('need', 'digest', 'replay', 'function_bytes', 'verify_overlay_inputs'))
    proof.verify_overlay_inputs(fixed, HOST_INPUTS)
    need(proof.OLD_NAV == OLD_RUNNER and proof.NEW_NAV == NEW_RUNNER, 'window_navigation_identity')
    for pin in (OLD_WORKER, WORKER, GENERATOR, DELTA, GENERATION):
        fixed(pin)
    spec = json.loads(HOST_INPUTS[DELTA[0]].decode('ascii'))
    need(set(spec) == {'schema', 'evidence', 'generator', 'source', 'runner', 'candidate',
                      'replacements', 'guards'} and
         spec['schema'] == 'p011-receive-window-clock-ui-v1-worker-delta' and
         spec['evidence'] == 'MECHANICAL_GENERATED_NOT_HOST_CHECKED' and
         spec['generator'] == list(GENERATOR) and spec['source'] == list(OLD_WORKER) and
         spec['runner'] == list(NEW_RUNNER) and spec['candidate'] == list(WORKER) and
         spec['replacements'] == list(EDITS) and spec['guards'] == GUARDS, 'worker_delta_identity')
    old, new = HOST_INPUTS[OLD_WORKER[0]], HOST_INPUTS[WORKER[0]]
    need(replay(old) == new and replay(new, True) == old and
         definitions_bytes(old) == definitions_bytes(new) and
         len(old.splitlines()) == len(new.splitlines()), 'worker_full_byte_inverse')
    generator = ast.parse(HOST_INPUTS[GENERATOR[0]], feature_version=(3, 5))
    rows = [row.value for row in generator.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
            isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'EDITS']
    need(len(rows) == 1 and isinstance(rows[0], ast.Tuple) and len(rows[0].elts) == 2,
         'worker_generator_identity')
    literal_edits = []
    for node in rows[0].elts:
        need(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
             node.func.id == 'dict' and not node.args and
             tuple(keyword.arg for keyword in node.keywords) == ('name', 'count', 'before', 'after'),
             'worker_generator_literal')
        literal_edits.append({keyword.arg: ast.literal_eval(keyword.value) for keyword in node.keywords})
    need(literal_edits == list(EDITS), 'worker_generator_edit_identity')
    FACTS.update(proof.FACTS)
    FACTS.update(new_navigation_runner_pin=list(NEW_RUNNER), new_worker_pin=list(WORKER),
        window_worker_exact_inverse_verified=True, worker_definition_bytes_unchanged=True,
        worker_line_numbers_unchanged=True, gui_rebuilt=False, gui_restaged=False,
        stage_entry_available=False, retained_window_projection_added=False)


def source_block(name, pin, raw, carrier):
    return ('sources[' + repr(name) + ']=decode((\n' + carrier.encoded(raw) +
            '),' + repr(pin[1]) + ',' + repr(pin[2]) + ')').encode('ascii')


def overlay_program(original, inputs, payload, runner, carrier, fresh):
    need(runner == OLD_RUNNER, 'base_program_runner')
    raw, wire = original(inputs, payload, runner, carrier)
    edits = [(source_block('worker', OLD_WORKER, inputs[OLD_WORKER[0]], carrier),
              source_block('worker', WORKER, inputs[WORKER[0]], carrier)),
             (source_block('runner', OLD_RUNNER, inputs[OLD_RUNNER[0]], carrier),
              source_block('runner', NEW_RUNNER, inputs[NEW_RUNNER[0]], carrier)),
             (b'code.co_firstlineno!=816', b'code.co_firstlineno!=817')]
    current = raw
    for old, new in edits:
        need(current.count(old) == 1, 'carrier_overlay_count')
        current = current.replace(old, new, 1)
    inverse = current
    for old, new in reversed(edits):
        need(inverse.count(new) == 1, 'carrier_overlay_inverse_count')
        inverse = inverse.replace(new, old, 1)
    need(inverse == raw and len(current) <= 2097152 and
         max(map(len, current.splitlines())) <= 2048 and len(wire) <= 6291456, 'carrier_overlay_inverse_budget')
    ast.parse(current, feature_version=(3, 5))
    fresh(HOST_OUT / 'private-base-navigation-bootstrap.py', raw)
    fresh(HOST_OUT / 'private-base-navigation-wire.raw', wire)
    FACTS.update(carrier_runner_worker_exact_inverse_verified=True,
        refusal_observer_line_rebound=817, public_schema_unchanged=True,
        navigation_program_bytes=len(current), navigation_program_max_line=max(map(len, current.splitlines())))
    return current, wire


def shape(node):
    return ast.dump(node, include_attributes=False)


def expression(source):
    return ast.parse(source, mode='eval').body


def composed_main(original, raw):
    """Single new main; finite mode/control delta with full AST inverse."""
    tree = original(raw)
    before = copy.deepcopy(tree)
    changes = []
    def change(parent, field, value):
        old = parent[field] if type(parent) is list else getattr(parent, field)
        changes.append((parent, field, copy.deepcopy(old)))
        if type(parent) is list:
            parent[field] = value
        else:
            setattr(parent, field, value)
    body = tree.body[0].body
    controls = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and len(row.targets) == 1 and
                isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'control']
    modes = [row for row in body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
             isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'mode']
    stage_arg = [row for row in body if isinstance(row, ast.Expr) and isinstance(row.value, ast.Call) and
                 shape(row.value.func) == shape(expression('modes.add_argument')) and row.value.args and
                 isinstance(row.value.args[0], ast.Constant) and row.value.args[0].value == '--stage-device']
    need(len(controls) == len(modes) == len(stage_arg) == 1 and
         shape(controls[0].value) == shape(expression(OLD_CONTROL)), 'main_identity_shape')
    change(controls[0], 'value', expression(NEW_CONTROL))
    change(modes[0], 'value', expression("'navigation-test' if args.navigation_test else 'source'"))
    change(body, body.index(stage_arg[0]), ast.Pass())
    attrs = [row for row in ast.walk(tree) if isinstance(row, ast.Attribute) and
             isinstance(row.value, ast.Name) and row.value.id == 'args' and row.attr == 'stage_device']
    need(len(attrs) == 1, 'stage_request_shape')
    for parent in ast.walk(tree):
        for field, child in ast.iter_fields(parent):
            for container, slot, item in ([(child, at, item) for at, item in enumerate(child)]
                                         if type(child) is list else [(parent, field, child)]):
                if item is attrs[0]:
                    change(container, slot, ast.Constant(value=False))
    stages = [(node.body, at) for node in ast.walk(tree) if isinstance(node, (ast.Try, ast.FunctionDef))
              for at, row in enumerate(node.body) if isinstance(row, ast.Assign) and len(row.targets) == 1 and
              isinstance(row.targets[0], ast.Subscript) and
              isinstance(row.targets[0].value, ast.Name) and row.targets[0].value.id == 'programs' and
              isinstance(row.targets[0].slice, ast.Constant) and row.targets[0].slice.value == 'stage']
    need(len(stages) == 1, 'stage_program_shape')
    change(stages[0][0], stages[0][1], ast.Pass())
    final = copy.deepcopy(tree)
    for parent, field, old in reversed(changes):
        if type(parent) is list:
            parent[field] = old
        else:
            setattr(parent, field, old)
    need(shape(tree) == shape(before), 'window_ui_main_exact_inverse')
    FACTS.update(window_ui_main_exact_inverse_verified=True, stage_program_composed=False,
        original_closed_policy_retained=True, ready_seconds=10, navigation_seconds=20,
        owner_seconds=600, cleanup_seconds=60, ui_outer_seconds=800, ui_host_seconds=810)
    return ast.fix_missing_locations(final)


def prepare():
    global UI
    verify_overlay()
    UI = pure(UI_HOST)
    need(UI.WORKER == OLD_WORKER and UI.NEW_RUNNER == OLD_RUNNER and UI.SEALER == SEALER,
         'frozen_ui_base_identity')
    UI.HOST_INPUTS, UI.EXTERNAL_INPUTS, UI.FACTS = HOST_INPUTS, EXTERNAL_INPUTS, FACTS
    UI.SEAL, UI.EVIDENCE, UI.EXTERNAL_EVIDENCE, UI.HOST_OUT = SEAL, EVIDENCE, EXTERNAL_EVIDENCE, HOST_OUT
    UI.READ_ME = READ_ME
    original_composed = UI.composed_main
    UI.composed_main = lambda raw: composed_main(original_composed, raw)
    driver = UI.prepare()  # Pure setup/compile only; frozen UI main is absent.
    need(len(driver.UI_FIELDS) == 51, 'original_51_field_schema')
    original_program = driver.ui_program
    driver.ui_program = lambda inputs, payload, runner, carrier: overlay_program(
        original_program, inputs, payload, runner, carrier, driver.write_new)
    # Inner SELF/CMDS remain the frozen base for its original input and budget
    # checks. The new wrapper/CMD actual inputs are additionally retained here.
    need(len(HOST_INPUTS[SELF]) <= 26624, 'new_host_source_budget')
    ast.parse(HOST_INPUTS[SELF], feature_version=(3, 5))
    return driver


def main():
    global SEAL, EVIDENCE, EXTERNAL_EVIDENCE, HOST_OUT
    need(sys.argv[1:] in ([], ['--navigation-test']) and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'fixed_pc_modes')
    HOST_OUT = BASE / 'results' / ('receive-window-clock-ui-v1-' +
        ('navigation-test-' if sys.argv[1:] else 'source-') +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    HOST_OUT.mkdir(parents=True, exist_ok=False)
    sealer_raw = (BASE / SEALER[0]).read_bytes()
    need((len(sealer_raw), digest(sealer_raw)) == SEALER[1:], 'fixed_sealer_pin')
    SEAL = types.ModuleType('fixed_window_ui_sealer')
    exec(compile(sealer_raw, str(BASE / SEALER[0]), 'exec'), SEAL.__dict__)
    EVIDENCE, EXTERNAL_EVIDENCE = SEAL.InputEvidence(HOST_INPUTS), SEAL.InputEvidence(EXTERNAL_INPUTS)
    try:
        for path in (SELF,) + CMDS:
            EVIDENCE.read(BASE / path, key=path)
        fixed(SEALER)
        driver = prepare()
    except BaseException as error:
        SEAL.fresh(HOST_OUT / 'private-raw/outer-error.private.txt', traceback.format_exc().encode('utf-8'))
        # Use only the proven finite seal helper after failure; no business or
        # archived main can run. Evidence is sealed before public result bytes.
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
    # The newly compiled driver's own finally/stock/capture/seal handles runtime
    # outcomes. Do not wrap it and accidentally publish a second result.
    return driver.main()


if __name__ == '__main__':
    raise SystemExit(main())
