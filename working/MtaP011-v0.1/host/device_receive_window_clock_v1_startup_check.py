"""Fixed window predicate overlay on the preserved durable core startup carrier.

Default SOURCE. Explicit --check-device retains original closed startup-close.
Only the separate stdin runner changes; runtime75, manifests, roots and GUI stay.
The actual frozen core main is selected and mechanically compiled as a new main,
never called as an archived entry. No generator, suite, UI, RF or phone runs here.
"""
import ast
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys
import traceback
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_window_clock_v1_startup_check.py'
CMDS = ('HOST_MTA_RECEIVE_WINDOW_CLOCK_V1_STARTUP_CHECK.cmd',
        'TEST_MTA_RECEIVE_WINDOW_CLOCK_V1_STARTUP.cmd')
CORE_HOST = ('host/device_receive_durable_state_v1_startup_check.py', 18445,
             'b3bf58eb9b02170a69dc54f44207f0e27f8ef6c565431590a1f5d39de39668fd')
OLD_CORE = ('candidate/formal-receive-durable-state-v1/runtime/mta_formal_receive_session.py',
            79202, '38b7345454df94b1f5742d8c2f6a91a4cd8d0b1262909d4deacea2d48456008e')
OLD_NAV = ('candidate/formal-receive-durable-ui-v1/runtime/mta_formal_receive_session.py',
           88773, 'a5dffa34a9dac7fdcc240dd59e1472448dbe7f076ec5d1240804401cbaa1c0a3')
PREFIX = 'candidate/receive-window-clock-v1/'
NEW_CORE = (PREFIX + 'runtime/mta_formal_receive_session.py', 79279,
            '88c3dc8daac2f4315affb7f439e01a7a60a9c764053019fe9043f891b676a5aa')
NEW_NAV = (PREFIX + 'runtime/mta_formal_receive_navigation_session.py', 88850,
           '2aa5c840d9df5293fe10d385060821269d5170da4261b751c49af091ccf31f48')
GENERATOR = (PREFIX + 'generate.py', 8591,
             'aacf1c4127d029f72480e05ade9214cbf3598166d34871b7b5e1ff27dca0dfc6')
DELTA = (PREFIX + 'exactsource-delta.json', 4316,
         '175a998a9e352a54ca8779bafd76fb6752e00db0526f7a93149009302f08b01a')
GENERATION = (PREFIX + 'generation.json', 1803,
              '1e508473c35590d9d043560481a65d55c489cf8c60a682ae6a71e8f3842e5624')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
EDITS = (
    dict(name='duration_matches_original_construction', count=1,
         before="                self.until - self.window_started_at == (\n"
                "                    600.0 if self.profile == 'receive-interactive-v1' else 60.0) and\n",
         after="                self.until == self.window_started_at + (\n"
               "                    600.0 if self.profile == 'receive-interactive-v1' else 60.0) and\n"),
    dict(name='cleanup_matches_original_construction_and_strict_positive_spans', count=1,
         before='                self.cleanup_until - self.until == 60.0)\n',
         after='                self.cleanup_until == self.until + 60.0 and\n'
               '                self.window_started_at < self.until < self.cleanup_until)\n'))
GUARDS = dict(actual_clock_reads_added=0, actual_device_window_values_collected=False,
    cleanup_seconds=60, complete_fixed_session_constructed=False, deadline_check_changed=False,
    device_executed=False, diagnostic_seconds=60, epsilon_added=False, identity_guards_unchanged=True,
    interactive_seconds=600, renewal_added=False, strict_positive_spans=True)
READ_ME = (b'Fixed finite-window predicate overlay on preserved durable core75 startup carrier.\n'
    b'Default SOURCE; explicit device mode retains original60+60, Startup10, alarm240/host250 and closed policy.\n'
    b'Only the separate stdin runner pin/encoding changes; all75 roles, manifests, roots, native/FC/GUI stay.\n'
    b'Two exact window_current edits match original addition construction and strict increasing deadlines.\n'
    b'Original identity guards, constructor, deadline clock check and all other function bytes stay.\n'
    b'No tolerance, clock read, renewal, new admission, generator, old main/suite/builder, UI, RF or phone action.\n'
    b'Original requestTrue-to-False startup envelope and resource/pending/stock/close predicates stay.\n'
    b'An optional bounded WINDOW_CLOCK_V1 scalar projection uses only retained values, not a new clock.\n'
    b'Exact inputs, base/selected carriers, stdout/stderr and exceptions remain private before public sealing.\n'
    b'Mathematical floating counterexamples are not recorded P011 failure values or phone acceptance.\n'
    b'SOURCE is not device runtime; startup-close is not navigation, full wireless restoration or transfer.\n')
PROJECTION = b'''if retained is not None:
 try:
  window=retained._window_retained
  t,u,c=retained.window_started_at,retained.until,retained.cleanup_until
  profile=retained.profile
  floats=all(type(value) is float for value in (t,u,c))
  row=dict(profile=profile if type(profile) is str and profile in ('diagnostic','receive-interactive-v1') else 'unknown')
  row['retained_identity']=type(window) is tuple and len(window)==4 and retained._window_original is window
  row['field_identities']=tuple(value is window[index] for index,value in enumerate((profile,t,u,c))) if row['retained_identity'] else ()
  row['float_hex']=tuple(value.hex() for value in (t,u,c)) if floats else ()
  cap=600.0 if type(profile) is str and profile=='receive-interactive-v1' else 60.0
  row['add_activity']=floats and u==t+cap
  row['add_cleanup']=floats and c==u+60.0
  row['subtract_activity']=floats and u-t==cap
  row['subtract_cleanup']=floats and c-u==60.0
  row['strict_positive_spans']=floats and t<u<c
  print('WINDOW_CLOCK_V1='+repr(row))
 except BaseException:
  print('WINDOW_CLOCK_V1=UNAVAILABLE')
'''
BOOT_INPUTS = {}
FACTS = {}
OUTER_OUT = None


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_fixed(name, pin=None):
    if (type(name) is not str or not name or '\\' in name or
            PurePosixPath(name).is_absolute() or re.fullmatch(r'[A-Za-z0-9_./-]+', name) is None or
            any(part in ('', '.', '..') for part in name.split('/'))):
        raise ValueError('fixed_path')
    path = BASE
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or
                getattr(value, 'st_file_attributes', 0) & 0x400): raise ValueError('fixed_ancestor')
    for index, part in enumerate(name.split('/')):
        path = path / part; value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise ValueError('fixed_link')
        if index < len(name.split('/')) - 1 and not stat.S_ISDIR(value.st_mode):
            raise ValueError('fixed_ancestor')
    if not stat.S_ISREG(value.st_mode) or not 0 < value.st_size <= 2 * 1024 * 1024:
        raise ValueError('fixed_file')
    before = metadata(value)
    with path.open('rb') as handle:
        opened = metadata(os.fstat(handle.fileno()))
        if os.name == 'nt':
            equal = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                     opened[3:6] == before[3:6])
        else: equal = opened == before
        if not equal: raise ValueError('fixed_identity')
        raw = handle.read(2 * 1024 * 1024 + 1)
        if metadata(os.fstat(handle.fileno())) != opened: raise ValueError('fixed_changed')
    if metadata(path.lstat()) != before or len(raw) != before[4]: raise ValueError('fixed_changed')
    if pin is not None and (len(raw), digest(raw)) != pin: raise ValueError('fixed_pin')
    return raw


def replay(raw, inverse=False):
    for row in reversed(EDITS) if inverse else EDITS:
        before = row['after' if inverse else 'before'].encode('ascii')
        after = row['before' if inverse else 'after'].encode('ascii')
        need(raw.count(before) == 1, 'window_delta_count')
        raw = raw.replace(before, after, 1)
    return raw


def function_bytes(raw, name):
    tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    classes = [row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == 'FixedSession']
    need(len(classes) == 1, 'runner_class')
    nodes = [row for row in classes[0].body if isinstance(row, ast.FunctionDef) and row.name == name]
    need(len(nodes) == 1 and not nodes[0].decorator_list, 'runner_function')
    node = nodes[0]; lines = raw.splitlines(keepends=True)
    left, right = sum(map(len, lines[:node.lineno-1])), sum(map(len, lines[:node.end_lineno]))
    return raw[left:right], left, right


def verify_overlay_inputs(fixed, inputs):
    for pin in (CORE_HOST, GENERATOR, DELTA, GENERATION, OLD_CORE, OLD_NAV, NEW_CORE, NEW_NAV):
        fixed(pin)
    spec = json.loads(inputs[DELTA[0]].decode('ascii'))
    need(set(spec) == {'schema', 'evidence', 'generator', 'entries', 'guards'} and
         spec['schema'] == 'p011-receive-window-clock-v1-mechanical-delta' and
         spec['evidence'] == 'MECHANICAL_GENERATED_NOT_HOST_CHECKED' and
         spec['generator'] == list(GENERATOR) and spec['guards'] == GUARDS and
         type(spec['entries']) is list and len(spec['entries']) == 2, 'window_delta_shape')
    for entry, role, old_pin, new_pin in zip(spec['entries'], ('ordinary', 'navigation'),
                                           (OLD_CORE, OLD_NAV), (NEW_CORE, NEW_NAV)):
        need(entry['role'] == role and entry['source'] == list(old_pin) and
             entry['candidate'] == list(new_pin) and entry['replacements'] == list(EDITS),
             'window_delta_identity')
        old, new = inputs[old_pin[0]], inputs[new_pin[0]]
        need(replay(old) == new and replay(new, True) == old, 'window_full_byte_inverse')
        old_fun, old_left, old_right = function_bytes(old, 'window_current')
        new_fun, new_left, new_right = function_bytes(new, 'window_current')
        need(replay(old_fun) == new_fun and old[:old_left] == new[:new_left] and
             old[old_right:] == new[new_right:], 'only_window_function_changed')
        for name in ('__init__', 'check'):
            need(function_bytes(old, name)[0] == function_bytes(new, name)[0], 'constructor_deadline_unchanged')
    start, end = b'    def original_receive_ui_cancelled_empty(self):\n', b'    def load_owner(self):\n'
    for nav_pin, core_pin in ((OLD_NAV, OLD_CORE), (NEW_NAV, NEW_CORE)):
        raw = inputs[nav_pin[0]]
        need(raw.count(start) == raw.count(end) == 1, 'navigation_observer_anchor')
        left, right = raw.index(start), raw.index(end)
        need(right-left == 9571 and digest(raw[left:right]) ==
             'a030215a7fb95f9524c11b6afd5998cfba7f26a241ae26a88b8156d6f2a6560c' and
             raw[:left] + raw[right:] == inputs[core_pin[0]], 'navigation_core_byte_relation')
    FACTS.update(window_exact_two_delta_verified=True, only_window_current_changed=True,
        constructor_and_deadline_bytes_unchanged=True, observer_bytes=9571,
        navigation_core_relation_verified=True, new_runner_pin=list(NEW_CORE),
        runtime75_modified=False, identity_guards_unchanged=True, epsilon_added=False,
        renewal_added=False, clock_reads_added=0, retained_window_projection_added=True,
        actual_device_failure_cause_verified=False)


def overlay_carriers(definitions, helpers, inputs, original, program, out, fresh):
    need(definitions.RUNNER == OLD_CORE, 'base_runner_identity')
    old_block = ('RUNNER_PIN=' + repr(OLD_CORE[1:]) + '\nRUNNER_ENCODED=(\n' +
        definitions._short_chunks(helpers, inputs[OLD_CORE[0]]) + '\n)\n').encode('ascii')
    new_block = ('RUNNER_PIN=' + repr(NEW_CORE[1:]) + '\nRUNNER_ENCODED=(\n' +
        definitions._short_chunks(helpers, inputs[NEW_CORE[0]]) + '\n)\n').encode('ascii')
    anchor = b'retained=session._RETAINED\n'
    def overlay(raw):
        need(raw.count(old_block) == 1 and raw.count(anchor) == 1, 'carrier_overlay_anchor')
        result = raw.replace(old_block, new_block, 1).replace(anchor, anchor + PROJECTION, 1)
        need(result.count(new_block) == 1 and result.count(anchor + PROJECTION) == 1 and
             result.replace(anchor + PROJECTION, anchor, 1).replace(new_block, old_block, 1) == raw,
             'carrier_complete_byte_inverse')
        need(len(result) <= 2097152 and max(map(len, result.splitlines())) <= 256, 'carrier_original_budget')
        ast.parse(result.decode('ascii'), feature_version=(3, 5))
        return result
    before = b'component=session.run_fixed(artifacts,False,receive_trial_requested=True)'
    after = b'component=session.run_fixed(artifacts,False,receive_trial_requested=False)'
    need(original.count(before) == program.count(after) == 1 and program.replace(after, before, 1) == original,
         'original_false_request_envelope')
    # The unchanged inner fresh() performs exclusive write and readback.
    fresh(out / 'private-base-original-service-target.py', original)
    fresh(out / 'private-base-startup-target.py', program)
    new_original, new_program = overlay(original), overlay(program)
    need(new_program.count(after) == 1 and new_program.replace(after, before, 1) == new_original,
         'overlay_false_request_envelope')
    FACTS.update(carrier_inverse_verified=True, original75_encoded_rows_unchanged=True,
        diagnostic_seconds=60, interactive_seconds=600, cleanup_seconds=60,
        startup_seconds=10, alarm_seconds=240, host_seconds=250, runner_is_separate_from_payload75=True)
    return new_original, new_program


def new_main(raw):
    source = ast.parse(raw, feature_version=(3, 5))
    rows = [row for row in source.body if isinstance(row, ast.FunctionDef) and row.name == 'main']
    need(len(rows) == 1, 'core_main_shape')
    original = ast.Module(body=rows, type_ignores=[])
    tree = copy.deepcopy(original); main = tree.body[0]
    changes = []
    def change(parent, field, value):
        changes.append((parent, field, copy.deepcopy(getattr(parent, field))))
        setattr(parent, field, value)
    assignments = [row for row in main.body if isinstance(row, ast.Assign) and len(row.targets) == 1]
    out_rows = [row for row in assignments if isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'out']
    input_rows = [row for row in assignments if isinstance(row.targets[0], ast.Tuple) and
                  tuple(target.id for target in row.targets[0].elts) == ('inputs', 'sealer', 'evidence')]
    need(len(out_rows) == len(input_rows) == 1 and isinstance(input_rows[0].value, ast.Tuple), 'main_state_bindings')
    change(out_rows[0], 'value', ast.Name(id='OUTER_OUT', ctx=ast.Load()))
    values = copy.deepcopy(input_rows[0].value)
    need(len(values.elts) == 3 and isinstance(values.elts[0], ast.Dict), 'main_input_assignment')
    values.elts[0] = ast.Name(id='BOOT_INPUTS', ctx=ast.Load())
    change(input_rows[0], 'value', values)
    identities = []
    for row in ast.walk(tree):
        if isinstance(row, ast.Constant) and type(row.value) is str:
            value = row.value.replace('receive-durable-state-v1-startup', 'receive-window-clock-v1-startup')
            value = value.replace('p011-receive-durable-v1-startup', 'p011-receive-window-clock-v1-startup')
            if value != row.value:
                identities.append(row); change(row, 'value', value)
    need(len(identities) == 3, 'main_report_label_count')
    blocks = [row for row in main.body if isinstance(row, ast.Try)]
    need(len(blocks) == 1, 'main_try_shape')
    body = blocks[0].body
    anchor = [index for index, row in enumerate(body) if isinstance(row, ast.Expr) and
              isinstance(row.value, ast.Call) and isinstance(row.value.func, ast.Name) and
              row.value.func.id == 'io_inverse']
    carriers = [index for index, row in enumerate(body) if isinstance(row, ast.Assign) and
                isinstance(row.value, ast.Call) and isinstance(row.value.func, ast.Attribute) and
                row.value.func.attr == 'make_source']
    need(len(anchor) == len(carriers) == 1, 'main_overlay_anchors')
    carrier_row = ast.parse('original, program = overlay_carriers(definitions, helpers, inputs, original, program, out, fresh)').body[0]
    body.insert(carriers[0]+1, carrier_row)
    input_rows = ast.parse('for path in WRAPPER_INPUTS:\n    read(path)\nverify_overlay_inputs(fixed, inputs)').body
    body[anchor[0]+1:anchor[0]+1] = input_rows
    reports = [index for index, row in enumerate(main.body) if isinstance(row, ast.Assign) and
               len(row.targets) == 1 and isinstance(row.targets[0], ast.Subscript) and
               isinstance(row.targets[0].slice, ast.Constant) and row.targets[0].slice.value == 'input_pins']
    need(len(reports) == 1, 'main_public_report_anchor')
    fact_row = ast.parse('report.update(window_overlay=dict(FACTS), selector_pin=list(CORE_HOST), old_main_called=False)').body[0]
    main.body.insert(reports[0], fact_row)
    final = copy.deepcopy(tree)
    main.body.remove(fact_row)
    for row in input_rows:
        body.remove(row)
    body.remove(carrier_row)
    for parent, field, before in reversed(changes):
        setattr(parent, field, before)
    need(ast.dump(tree, include_attributes=False) == ast.dump(original, include_attributes=False),
         'new_main_complete_ast_inverse')
    FACTS['host_ast_inverse_verified'] = True
    return ast.fix_missing_locations(final)


def main():
    global OUTER_OUT
    need(sys.argv[1:] in ([], ['--check-device']), 'fixed_entry_modes')
    OUTER_OUT = BASE / 'results' / ('receive-window-clock-v1-startup-' +
        ('device-' if sys.argv[1:] else 'source-') + datetime.datetime.now().strftime('%Y%m%d-%H%M%S') +
        '-' + secrets.token_hex(4))
    try:
        for path in (SELF,) + CMDS + (CORE_HOST[0],):
            BOOT_INPUTS[path] = read_fixed(path)
        raw = BOOT_INPUTS[CORE_HOST[0]]
        need((len(raw), digest(raw)) == CORE_HOST[1:], 'frozen_core_host_pin')
        tree = ast.parse(raw, feature_version=(3, 5))
        nodes = [row for row in tree.body if isinstance(row, (ast.Import, ast.ImportFrom, ast.Assign)) or
                 isinstance(row, ast.FunctionDef) and row.name != 'main']
        scope = types.ModuleType('new_fixed_window_core_startup')
        scope.__file__ = str(BASE / CORE_HOST[0])
        exec(compile(ast.Module(body=nodes, type_ignores=[]), scope.__file__, 'exec'), scope.__dict__)
        need('main' not in scope.__dict__ and scope.SELF == CORE_HOST[0], 'inner_core_self_binding')
        scope.__dict__.update(OUTER_OUT=OUTER_OUT, BOOT_INPUTS=BOOT_INPUTS,
            WRAPPER_INPUTS=(SELF,) + CMDS, CORE_HOST=CORE_HOST, FACTS=FACTS, READ_ME=READ_ME,
            verify_overlay_inputs=verify_overlay_inputs, overlay_carriers=overlay_carriers)
        exec(compile(new_main(raw), str(BASE / SELF), 'exec'), scope.__dict__)
    except BaseException as failure:
        OUTER_OUT.mkdir(parents=True, exist_ok=True)
        private = OUTER_OUT / 'private-raw'; private.mkdir(exist_ok=True)
        raw = traceback.format_exc().encode('utf-8')
        with (private / 'outer-error.private.txt').open('xb') as stream:
            need(stream.write(raw) == len(raw), 'outer_error_write')
        for path, value in BOOT_INPUTS.items():
            target = OUTER_OUT / 'private-inputs' / path
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                with target.open('xb') as stream:
                    need(stream.write(value) == len(value), 'bootstrap_input_write')
        sealer_raw = read_fixed(SEALER[0], SEALER[1:])
        sealer = types.ModuleType('fixed_window_bootstrap_sealer')
        exec(compile(sealer_raw, str(BASE / SEALER[0]), 'exec'), sealer.__dict__)
        report = dict(schema='p011-receive-window-clock-v1-startup', mode='device' if sys.argv[1:] else 'source',
            passed=False, error=type(failure).__name__, source_checked=False, source_preserved=False,
            device_invoked=False, device_execution_unknown=bool(sys.argv[1:]), phone_requested=False,
            rf_action_requested=False, old_main_called=False, input_pins=[dict(path=path, bytes=len(value),
                sha256=digest(value)) for path, value in BOOT_INPUTS.items()])
        sealed = sealer.seal_result(OUTER_OUT, report, READ_ME)
        print(json.dumps(dict(passed=False, result_dir=str(OUTER_OUT),
            public_result_zip=str(sealed['archive']) if sealed['archive'] else None,
            zip_sha256=sealed['archive_sha256']), sort_keys=True))
        return 1
    # This is the new mechanically compiled main; its own sealed failure path
    # is not wrapped in a second publication attempt after device execution.
    return scope.main()


if __name__ == '__main__':
    raise SystemExit(main())
