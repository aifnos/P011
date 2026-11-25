"""Independent atomic-empty Worker carrier over frozen frame-v2 pure prepare.

Default SOURCE or explicit navigation-test; no archived main/suite/stage.
Only the Worker encoded block and exclusive CONTROL are overlaid. The original
51-field PASS, finally, closure, capture, deadlines and refusal binding remain.
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
SELF = 'host/device_receive_navigation_atomic_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_NAVIGATION_ATOMIC_V1_SOURCE_CHECK.cmd',
        'TEST_MTA_RECEIVE_NAVIGATION_ATOMIC_V1.cmd')
CURRENT = ('host/device_receive_navigation_frame_v2_check.py', 13717,
           '4ae5a18c3caccf00cf7a8271099674473cb5df9be828b6367c98f7ed6e02e17d')
SOURCE = ('candidate/receive-navigation-frame-v2/runtime/ui_session.py', 95351,
          '0c53b23051e5d79cdc392b2f89d3d21de2425028ff4f76292284a72f631cb4fe')
PREFIX = 'candidate/receive-navigation-atomic-v1/'
WORKER = (PREFIX + 'runtime/ui_session.py', 100162,
          'cde8ae626632e5d86acb2cc741b7d22eb18582b58ed6d6fd48160c008b62225e')
GENERATOR = (PREFIX + 'generate.py', 11019,
             '7a2cbc24c19c850c17244162ca033bf83e8b39246e901becc418fbe265e1f12d')
DELTA = (PREFIX + 'exactsource-delta.json', 7470,
         '9af5097dda522efa3bd9b5f406308f3c43123e7159a1ef78251d835b8dd35613')
GENERATION = (PREFIX + 'generation.json', 1472,
              'bea9c4b9f0bca12c1dbbb6d570a925cdc2a4daf144c3f81c30eb123987f3de49')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
EDIT_NAMES = ('exclusive_control_suffix', 'retain_after_successful_original_load_owner_same_line',
              'atomic_pair_preserves_three_lines_and_cached_four_guard',
              'helper_after_run_fixed_before_source_only_main')
GUARDS = dict(original_predicates_reused=True, cached_four_guards_unchanged=True,
              run_fixed_line=1246, navigation_failure_line=1560, runner_observer_line=817,
              state_then_trial_original_rlocks=True, original_locks_once_retained=True,
              runtime75_modified=False, runner_modified=False, gui_rebuilt=False,
              gui_staged=False, public_fields=51, startup_seconds=10,
              service_seconds=600, cleanup_seconds=60, new_clock_calls=0,
              new_probe_calls=0, device_executed=False, tests_executed=False)
OLD_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-receive-navigation-frame-v2'"
NEW_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-receive-navigation-atomic-v1'"
READ_ME = (b'Frozen frame-v2 pure prepare; SOURCE or explicit navigation-test only, never stage.\n'
           b'Only new CONTROL and the pinned atomic Worker encoded block are overlaid.\n'
           b'Worker uses the two original empty predicates under retained original State then Trial RLocks.\n'
           b'Original cached four guards, public51/PASS/failures/finally/capture and10/600+60/20/READY10 caps stay.\n'
           b'Existing refusal helper frame1560/Runner817 and namespace/code/type/limits64 remain exact.\n'
           b'No runtime75/Runner/Factory/GUI20 rebuild or restage, new clock/probe or automatic RF action.\n'
           b'Complete Worker/carrier byte and AST inverses, original definition lines and private raw are retained.\n'
           b'SOURCE is not P011 navigation, phone, RF, receive admission or full restoration acceptance.\n')
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
    value = types.ModuleType('fixed_navigation_atomic_v1_frame_pure')
    value.__file__ = str(BASE / CURRENT[0])
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                 value.__file__, 'exec'), value.__dict__)
    need('main' not in value.__dict__ and value.WORKER == SOURCE and value.SEALER == SEALER,
         'current_pure_identity')
    for name in ('HOST_INPUTS', 'EXTERNAL_INPUTS', 'FACTS', 'SEAL', 'EVIDENCE',
                 'EXTERNAL_EVIDENCE', 'HOST_OUT', 'READ_ME'):
        value.__dict__[name] = globals()[name]
    return value


def generator_literals(raw):
    """Read only fixed literals; do not import or execute the generator."""
    tree = ast.parse(raw, feature_version=(3, 5))
    def assignment(name):
        rows = [row.value for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
                isinstance(row.targets[0], ast.Name) and row.targets[0].id == name]
        need(len(rows) == 1, 'generator_assignment:' + name)
        return rows[0]
    helper = ast.literal_eval(assignment('HELPER'))
    need(type(helper) is str and helper.startswith('def _receive_ui_empty_pair(component):\n'),
         'generator_helper_literal')
    def literal(node):
        if isinstance(node, ast.BinOp):
            need(isinstance(node.op, ast.Add) and isinstance(node.left, ast.Name) and
                 node.left.id == 'HELPER' and type(ast.literal_eval(node.right)) is str,
                 'generator_helper_concat')
            return helper + ast.literal_eval(node.right)
        return ast.literal_eval(node)
    def dictionary(node, names=None):
        need(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'dict' and
             not node.args and all(row.arg is not None for row in node.keywords) and
             (names is None or tuple(row.arg for row in node.keywords) == names), 'generator_dict_shape')
        return {row.arg: literal(row.value) for row in node.keywords}
    edits = assignment('EDITS')
    need(isinstance(edits, ast.Tuple) and len(edits.elts) == 4, 'generator_four_edits')
    rows = [dictionary(row, ('name', 'count', 'before', 'after')) for row in edits.elts]
    need(tuple(row['name'] for row in rows) == EDIT_NAMES and
         all(type(row['count']) is int and row['count'] == 1 and
             type(row['before']) is type(row['after']) is str for row in rows) and
         dictionary(assignment('GUARDS')) == GUARDS and
         ast.literal_eval(assignment('SOURCE')) == SOURCE, 'generator_literal_identity')
    return rows


def verify_worker():
    for pin in (SOURCE, WORKER, GENERATOR, DELTA, GENERATION):
        fixed(pin)
    edits = generator_literals(HOST_INPUTS[GENERATOR[0]])
    delta = json.loads(HOST_INPUTS[DELTA[0]].decode('ascii'))
    need(delta == dict(
        schema='p011-receive-navigation-atomic-v1-worker-delta',
        evidence='MECHANICAL_GENERATED_NOT_HOST_CHECKED', generator=list(GENERATOR),
        source=list(SOURCE), candidate=list(WORKER), replacements=edits, guards=GUARDS),
        'worker_delta_identity')
    edits = delta['replacements']  # Replay the exact retained/pinned delta.
    need(json.loads(HOST_INPUTS[GENERATION[0]].decode('ascii')) == dict(
        schema='p011-receive-navigation-atomic-v1-generation', status='MECHANICAL_GENERATED_NOT_HOST_CHECKED',
        generator=list(GENERATOR), source=list(SOURCE), outputs=[list(pin) for pin in sorted((WORKER, DELTA))],
        guards=GUARDS, host_checked=False, phone_tested=False), 'generation_identity')
    def replay(raw, inverse=False):
        for row in reversed(edits) if inverse else edits:
            before = row['after' if inverse else 'before'].encode('ascii')
            after = row['before' if inverse else 'after'].encode('ascii')
            need(raw.count(before) == 1, 'worker_edit_count:' + row['name'])
            raw = raw.replace(before, after, 1)
        return raw
    old, new = HOST_INPUTS[SOURCE[0]], HOST_INPUTS[WORKER[0]]
    forward, inverse = replay(old), replay(new, True)
    need(forward == new and inverse == old and
         shape(ast.parse(forward, feature_version=(3, 5))) == shape(ast.parse(new, feature_version=(3, 5))) and
         shape(ast.parse(inverse, feature_version=(3, 5))) == shape(ast.parse(old, feature_version=(3, 5))),
         'worker_complete_byte_ast_inverse')
    def definitions(raw):
        lines = raw.splitlines(keepends=True)
        return {row.name: (row.lineno, row.end_lineno, b''.join(lines[row.lineno - 1:row.end_lineno]))
                for row in ast.parse(raw, feature_version=(3, 5)).body
                if isinstance(row, (ast.FunctionDef, ast.ClassDef))}
    before, after = definitions(old), definitions(new)
    need(set(after) == set(before) | {'_receive_ui_empty_pair'} and
         all(after[name] == value for name, value in before.items() if name != 'run_fixed') and
         before['run_fixed'][:2] == after['run_fixed'][:2] and after['run_fixed'][0] == 1246 and
         after['need'][0] == 112 and
         new.splitlines(keepends=True)[1559] == b"                     'navigation_receive_activity')\n",
         'original_definitions_and_refusal_lines')
    FACTS.update(navigation_atomic_worker_complete_byte_ast_inverse_verified=True,
        navigation_atomic_other_definitions_exact=True, navigation_atomic_worker_pin=list(WORKER),
        navigation_atomic_generator_not_executed=True, navigation_atomic_four_edits_verified=True,
        navigation_atomic_run_fixed_line=1246, navigation_atomic_failure_line=1560,
        navigation_atomic_runner_line=817, navigation_atomic_original_predicates_reused=True)


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
    FACTS['navigation_atomic_main_complete_ast_inverse_verified'] = True
    return ast.fix_missing_locations(final)


def overlay_program(original, inputs, payload, runner, carrier, fresh):
    raw, wire = original(inputs, payload, runner, carrier)
    def block(pin):
        return ("sources['worker']=decode((\n" + carrier.encoded(inputs[pin[0]]) +
                '),' + repr(pin[1]) + ',' + repr(pin[2]) + ')').encode('ascii')
    before, after = block(SOURCE), block(WORKER)
    need(raw.count(before) == 1, 'carrier_worker_count')
    new = raw.replace(before, after, 1)
    need(new.count(after) == 1, 'carrier_worker_inverse_count')
    inverse = new.replace(after, before, 1)
    need(inverse == raw and shape(ast.parse(inverse, feature_version=(3, 5))) ==
         shape(ast.parse(raw, feature_version=(3, 5))) and len(new) <= 2097152 and
         max(map(len, new.splitlines())) <= 2048 and len(wire) <= 6291456 and
         raw.count(b'tb.tb_lineno!=1560') == new.count(b'tb.tb_lineno!=1560') == 1 and
         raw.count(b'code.co_firstlineno!=817') == new.count(b'code.co_firstlineno!=817') == 1,
         'carrier_complete_byte_ast_inverse_budget_refusal')
    ast.parse(new, feature_version=(3, 5))
    fresh(HOST_OUT / 'private-current-frame-v2-bootstrap.py', raw)
    fresh(HOST_OUT / 'private-current-frame-v2-wire.raw', wire)
    FACTS.update(navigation_atomic_carrier_complete_byte_ast_inverse_verified=True,
        navigation_atomic_refusal_fragment_unchanged=True, navigation_atomic_program_bytes=len(new),
        navigation_atomic_program_max_line=max(map(len, new.splitlines())))
    return new, wire


def prepare():
    current = current_pure()
    verify_worker()
    original_main = current.main_overlay
    current.main_overlay = lambda tree: main_overlay(original_main(tree))
    driver = current.prepare()  # Frozen definitions only; archived main is absent.
    need(len(driver.UI_FIELDS) == 51 and len(HOST_INPUTS[SELF]) <= 26624, 'original_schema_host_budget')
    original_program = driver.ui_program
    driver.ui_program = lambda inputs, payload, runner, carrier: overlay_program(
        original_program, inputs, payload, runner, carrier, driver.write_new)
    return driver


def main():
    global SEAL, EVIDENCE, EXTERNAL_EVIDENCE, HOST_OUT
    need(sys.argv[1:] in ([], ['--navigation-test']) and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'fixed_pc_modes')
    mode = 'navigation-test' if sys.argv[1:] else 'source'
    HOST_OUT = BASE / 'results' / ('receive-navigation-atomic-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    HOST_OUT.mkdir(parents=True, exist_ok=False)
    sealer_raw = (BASE / SEALER[0]).read_bytes()
    need((len(sealer_raw), digest(sealer_raw)) == SEALER[1:], 'fixed_sealer_pin')
    SEAL = types.ModuleType('fixed_navigation_atomic_v1_sealer')
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
