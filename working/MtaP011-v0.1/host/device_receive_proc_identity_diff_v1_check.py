"""Frozen atomic-navigation carrier plus one passive Proc identity projection.

Default SOURCE or explicit navigation-test only. Pure prepare excludes archived
main/guards. The new diagnostic follows the complete original PROC fragment;
only the exclusive CONTROL constant is mechanically changed in the in-memory
Worker and composed HOST main. All original business, 51-field PASS, caps,
finally, capture, closure, admission and frozen runtime75/GUI assets stay exact.
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
SELF = 'host/device_receive_proc_identity_diff_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_PROC_IDENTITY_DIFF_V1_SOURCE_CHECK.cmd',
        'TEST_MTA_RECEIVE_PROC_IDENTITY_DIFF_V1.cmd')
CURRENT = ('host/device_receive_navigation_atomic_v1_check.py', 15264,
           '30695a4928e1895f77ec95fb6519269eec2a3498c2a5a225b52cb83d9f919388')
WORKER = ('candidate/receive-navigation-atomic-v1/runtime/ui_session.py', 100162,
          'cde8ae626632e5d86acb2cc741b7d22eb18582b58ed6d6fd48160c008b62225e')
PROC = ('host/receive_startup_proc_projection_v1.py', 6137,
        'aae15e0726ae21c2d1f8b97e8249123465c67191e2928f607e149acadd264002')
DIAGNOSTIC = ('host/receive_startup_proc_identity_diff_v1.py', 16789,
              '6712eaadd8bab1b29e1eeed3854bfe35b56c52b2d605adf31521c6e44e99eafa')
FRAGMENT_PIN = (15182, '3c0045b51f88dcf82b55a437526329361cd138b7f529f0631b7bc8e0c3bbd608')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
OLD_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-receive-navigation-atomic-v1'"
NEW_CONTROL = "'/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-receive-proc-identity-diff-v1'"
OLD_CONTROL_NAME = "'p011-mta-ui-session-' + SESSION + '-receive-navigation-atomic-v1'"
NEW_CONTROL_NAME = "'p011-mta-ui-session-' + SESSION + '-receive-proc-identity-diff-v1'"
RETURNED = b'component=worker.run_fixed(sources["runner"],tuple(artifacts),sources["assets"],navigation_test=True,filecenter_sources=tuple(fc))\n'
RESULT = b'print("RESULT="+repr(component));print("MTA_REMOTE_OK")\n'
READ_ME = (b'Frozen atomic-navigation pure prepare; default SOURCE or explicit navigation-test only.\n'
           b'New Proc identity DATA follows the complete original PROC projection after run_fixed returns.\n'
           b'Only ended retained history/tickets/raw records and original error traceback are inspected.\n'
           b'No clock/resource IO/reader/guard/stable_key/directory/parser/callback is invoked by the diagnostic.\n'
           b'Pid/start/comm/flags/ppid equality flags and flags XOR are private bounded DATA, not raw identities.\n'
           b'Directory equality is None unless the original final directory record actually exists.\n'
           b'Unknown/not-applicable DATA never changes original public51/PASS/failures/finally/closure/admission.\n'
           b'Worker derives only the unique CONTROL_NAME constant line in memory; all definitions/lines stay exact.\n'
           b'HOST control synchronizes that suffix; original Worker source/input pin and old files remain unchanged.\n'
           b'Derived Worker bytes/pin and complete carrier/main inverses are retained with private input/raw evidence.\n'
           b'No runtime75/Runner/Factory/GUI20 rebuild or staging, phone/RF action or historical main/suite replay.\n'
           b'Original10/600+60/20/READY10 and800/HOST810 caps; bootstrap2MiB/line2048/wire6MiB/HOST26KiB stay.\n'
           b'SOURCE is not P011 UI/navigation, phone handshake, receive admission, RF or full restoration acceptance.\n')
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
    value = types.ModuleType('fixed_proc_identity_diff_atomic_pure')
    value.__file__ = str(BASE / CURRENT[0])
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                 value.__file__, 'exec'), value.__dict__)
    need('main' not in value.__dict__ and value.SELF == CURRENT[0] and
         value.WORKER == WORKER and value.SEALER == SEALER, 'current_pure_identity')
    for name in ('HOST_INPUTS', 'EXTERNAL_INPUTS', 'FACTS', 'SEAL', 'EVIDENCE',
                 'EXTERNAL_EVIDENCE', 'HOST_OUT', 'READ_ME'):
        value.__dict__[name] = globals()[name]
    return value


def literal_fragment(pin):
    """Read a pinned literal only; never import or call the helper's main."""
    tree = ast.parse(fixed(pin), feature_version=(3, 5))
    rows = [row.value for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
            isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'TARGET_FRAGMENT']
    aliases = [row.value for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
               isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'DIAGNOSTIC_RAW']
    need(len(rows) == len(aliases) == 1 and isinstance(aliases[0], ast.Name) and
         aliases[0].id == 'TARGET_FRAGMENT', 'fragment_literal_alias_shape')
    fragment = ast.literal_eval(rows[0])
    need(type(fragment) is bytes and fragment.endswith(b'\n') and
         0 < len(fragment) <= 16384 and max(map(len, fragment.splitlines())) <= 2048,
         'fragment_literal_budget')
    ast.parse(fragment, feature_version=(3, 5))
    return fragment


def fragments():
    original = literal_fragment(PROC)
    fragment = literal_fragment(DIAGNOSTIC)
    need((len(fragment), digest(fragment)) == FRAGMENT_PIN and len(original) <= 6144,
         'fragment_actual_identity')
    tree = ast.parse(fragment, feature_version=(3, 5))
    need(len(tree.body) == 2 and isinstance(tree.body[0], ast.FunctionDef) and
         tree.body[0].name == '_receive_startup_proc_identity_diff_v1' and
         not tree.body[0].decorator_list and isinstance(tree.body[1], ast.Try),
         'single_pure_projection_and_output')
    calls = [row for row in ast.walk(tree.body[1]) if isinstance(row, ast.Call) and
             isinstance(row.func, ast.Name) and row.func.id == '_receive_startup_proc_identity_diff_v1']
    need(len(calls) == 1 and shape(calls[0]) == shape(ast.parse(
        '_receive_startup_proc_identity_diff_v1(worker, globals())', mode='eval').body),
        'single_projection_original_context_call')
    need(not any(isinstance(row, (ast.FunctionDef, ast.ClassDef)) for row in ast.walk(tree.body[1])),
         'output_tail_no_extra_definitions')
    FACTS.update(proc_identity_diff_fragment_bytes=len(fragment),
        proc_identity_diff_fragment_sha256=digest(fragment), proc_identity_diff_helper_main_called=False,
        proc_identity_diff_original_proc_fragment_unchanged=True, proc_identity_diff_after_original_return=True,
        proc_identity_diff_prior_proc_completed_context=True, proc_identity_diff_public_fields_added=0,
        proc_identity_diff_new_clock=False, proc_identity_diff_new_resource_io=False,
        proc_identity_diff_original_guard_called=False, proc_identity_diff_retained_generation='history[-1]',
        proc_identity_diff_traceback_limit=64, proc_identity_diff_generation_limit=8320,
        proc_identity_diff_ticket_limit=280, proc_identity_diff_raw_record_limit=4096)
    return original, fragment


def main_overlay(tree):
    before = copy.deepcopy(tree)
    rows = [row for row in ast.walk(tree) if isinstance(row, ast.Assign) and len(row.targets) == 1 and
            isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'control']
    need(len(rows) == 1 and shape(rows[0].value) == shape(ast.parse(OLD_CONTROL, mode='eval').body),
         'main_original_control_shape')
    original = rows[0].value
    rows[0].value = ast.parse(NEW_CONTROL, mode='eval').body
    final = copy.deepcopy(tree)
    rows[0].value = original
    need(shape(tree) == shape(before), 'main_complete_ast_inverse')
    FACTS['proc_identity_diff_main_complete_ast_inverse_verified'] = True
    return ast.fix_missing_locations(final)


def derived_worker():
    """The actual fixed input remains unchanged; derive one constant in memory."""
    old = fixed(WORKER)
    core = ('CONTROL_NAME = ' + OLD_CONTROL_NAME).encode('ascii')
    choices = [line for line in (core + b'\n', core + b'\r\n') if old.count(line) == 1]
    need(len(choices) == 1, 'worker_control_complete_line_count')
    before = choices[0]
    after = before.replace(b'-receive-navigation-atomic-v1', b'-receive-proc-identity-diff-v1', 1)
    new = old.replace(before, after, 1)
    need(new.count(after) == 1 and new.replace(after, before, 1) == old and
         len(new.splitlines()) == len(old.splitlines()), 'worker_complete_byte_inverse')
    tree = ast.parse(old, feature_version=(3, 5))
    original = copy.deepcopy(tree)
    rows = [row for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
            isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'CONTROL_NAME']
    need(len(rows) == 1 and shape(rows[0].value) == shape(ast.parse(OLD_CONTROL_NAME, mode='eval').body),
         'worker_original_control_ast')
    previous = rows[0].value
    rows[0].value = ast.parse(NEW_CONTROL_NAME, mode='eval').body
    need(shape(tree) == shape(ast.parse(new, feature_version=(3, 5))), 'worker_complete_ast_forward')
    rows[0].value = previous
    need(shape(tree) == shape(original) and
         shape(ast.parse(new.replace(after, before, 1), feature_version=(3, 5))) == shape(original),
         'worker_complete_ast_inverse')
    def definitions(raw):
        lines = raw.splitlines(keepends=True)
        return [(row.name, row.lineno, row.end_lineno, b''.join(lines[row.lineno - 1:row.end_lineno]))
                for row in ast.parse(raw, feature_version=(3, 5)).body
                if isinstance(row, (ast.FunctionDef, ast.ClassDef))]
    need(definitions(old) == definitions(new), 'worker_all_definitions_and_lines_exact')
    pin = (len(new), digest(new))
    FACTS.update(proc_identity_diff_source_worker_pin=list(WORKER),
        proc_identity_diff_derived_worker_pin=list(pin),
        proc_identity_diff_worker_complete_byte_ast_inverse_verified=True,
        proc_identity_diff_worker_all_definition_bytes_lines_unchanged=True,
        proc_identity_diff_worker_delta='exclusive_control_name_complete_line_only',
        proc_identity_diff_runtime75_modified=False, proc_identity_diff_runner_modified=False,
        proc_identity_diff_gui_rebuilt=False, proc_identity_diff_gui_staged=False)
    return new, pin


def overlay_program(original, inputs, payload, runner, carrier, values, fresh):
    raw, wire = original(inputs, payload, runner, carrier)
    proc, fragment = values
    worker, pin = derived_worker()
    need(inputs[WORKER[0]] == HOST_INPUTS[WORKER[0]], 'original_worker_input_binding')
    def block(value, source_pin):
        return ("sources['worker']=decode((\n" + carrier.encoded(value) +
                '),' + repr(source_pin[0]) + ',' + repr(source_pin[1]) + ')').encode('ascii')
    before = block(inputs[WORKER[0]], WORKER[1:])
    after = block(worker, pin)
    need(raw.count(RETURNED) == raw.count(RESULT) == raw.count(proc) == 1 and
         raw.index(RETURNED) + len(RETURNED) <= raw.index(proc) and
         raw.index(proc) + len(proc) < raw.index(RESULT) and raw.count(fragment) == 0,
         'original_after_return_proc_unique_order')
    edits = ((before, after), (proc, proc + fragment))
    value = raw
    for old, new in edits:
        need(value.count(old) == 1, 'carrier_overlay_count')
        value = value.replace(old, new, 1)
    inverse = value
    for old, new in reversed(edits):
        need(inverse.count(new) == 1, 'carrier_inverse_count')
        inverse = inverse.replace(new, old, 1)
    need(inverse == raw and shape(ast.parse(inverse, feature_version=(3, 5))) ==
         shape(ast.parse(raw, feature_version=(3, 5))) and len(value) <= 2097152 and
         max(map(len, value.splitlines())) <= 2048 and len(wire) <= 6291456,
         'carrier_complete_byte_ast_inverse_budget')
    need(value.count(proc + fragment) == value.count(RETURNED) == value.count(RESULT) == 1 and
         value.index(RETURNED) + len(RETURNED) <= value.index(proc) and
         value.index(proc) + len(proc) == value.index(fragment) and
         value.index(fragment) + len(fragment) < value.index(RESULT) and
         raw.count(b'tb.tb_lineno!=1560') == value.count(b'tb.tb_lineno!=1560') == 1 and
         raw.count(b'code.co_firstlineno!=817') == value.count(b'code.co_firstlineno!=817') == 1,
         'carrier_context_order_original_refusal_binding')
    ast.parse(value, feature_version=(3, 5))
    fresh(HOST_OUT / 'private-current-navigation-atomic-bootstrap.py', raw)
    fresh(HOST_OUT / 'private-current-navigation-atomic-wire.raw', wire)
    fresh(HOST_OUT / 'private-derived-proc-identity-diff-worker.py', worker)
    FACTS.update(proc_identity_diff_carrier_complete_byte_ast_inverse_verified=True,
        proc_identity_diff_fragment_adjacent_to_original_proc=True,
        proc_identity_diff_original_result_and_refusal_unchanged=True,
        proc_identity_diff_program_bytes=len(value),
        proc_identity_diff_program_max_line=max(map(len, value.splitlines())))
    return value, wire


def prepare():
    current = current_pure()
    values = fragments()
    original_main = current.main_overlay
    current.main_overlay = lambda tree: main_overlay(original_main(tree))
    driver = current.prepare()  # Pure definitions only; archived main is absent.
    need(len(driver.UI_FIELDS) == 51 and len(HOST_INPUTS[SELF]) <= 26624,
         'original_schema_host_budget')
    original_program = driver.ui_program
    driver.ui_program = lambda inputs, payload, runner, carrier: overlay_program(
        original_program, inputs, payload, runner, carrier, values, driver.write_new)
    return driver


def main():
    global SEAL, EVIDENCE, EXTERNAL_EVIDENCE, HOST_OUT
    need(sys.argv[1:] in ([], ['--navigation-test']) and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'fixed_pc_modes')
    mode = 'navigation-test' if sys.argv[1:] else 'source'
    HOST_OUT = BASE / 'results' / ('receive-proc-identity-diff-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    HOST_OUT.mkdir(parents=True, exist_ok=False)
    sealer_raw = (BASE / SEALER[0]).read_bytes()
    need((len(sealer_raw), digest(sealer_raw)) == SEALER[1:], 'fixed_sealer_pin')
    SEAL = types.ModuleType('fixed_proc_identity_diff_v1_sealer')
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
