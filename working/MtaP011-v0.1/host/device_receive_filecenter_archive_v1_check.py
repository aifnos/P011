"""PC-only FileCenter UI and completed-receive-archive SOURCE assembly.

The frozen integrated ordinary36/Boot34/private35 graph is reused byte-for-byte.
No business graph, Qt, native, transport, device, old checker main or test runs
here. The new UI worker chooses archive True only in its fixed constructor.
No browser/API flag can choose that policy. Three private target programs are
generated, never executed: UI(True), default service(False), enabled service(True).
Raw graph76 <=4MiB, each program <=2MiB and each physical line <=256 remain fixed.
The separate exact9 FileCenter payload is bounded to131072 bytes. Built b6 GUI
assets are verified/snapshotted but not installed or dispatched by these programs.
SOURCE success does not prove receive, completed archive, radio restore or UI.
"""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_filecenter_archive_v1_check.py'
CMD = 'candidate/receive-filecenter-archive-v1/HOST_SOURCE.cmd'
INTEGRATED = ('host/device_receive_completed_archive_integrated_v1_check.py', 41826,
              '857f7dae7fa852dce52c1d68474eca44414c77977f6ab89f9d8098735e22eef5')
FILECENTER = ('host/device_receive_filecenter_v1_check.py', 67179,
              'da6a5a4dd78ef03156d1b4675e1081f4dbda5b6c9d4623cc9ddc549a5f564510')
WORKER = ('candidate/receive-filecenter-archive-v1/runtime/ui_session.py', 104680,
          '04d3bbbbda2bccf67b29154a5b481d70cecb17647dc8cec51eb045c679d24a7c')
MAX_PROGRAM = 2097152
MAX_GRAPH_RAW = 4194304
MAX_FILECENTER_RAW = 131072
EXPECTED_FILECENTER_RAW = 91295
EXPECTED_GRAPH_COUNT = 76
EXPECTED_BASE_INPUTS = 74
EXPECTED_BUNDLE_COUNT = 19
EXPECTED_BUNDLE_RAW = 4182249
ARCHIVE_BOOL_FIELDS = ('requested', 'attempted', 'archived', 'rename_called',
    'rename_outcome_known', 'archive_outcome_unknown', 'resources_closed',
    'native_restore_grant', 'receive_admission')
ARCHIVE_REASONS = ('not_attempted', 'archived', 'not_requested', 'source_changed',
    'owner_changed', 'receive_not_completed', 'factory_unknown', 'parent_unknown',
    'terminal_unknown', 'journal_unknown', 'marker_present', 'unsafe_path',
    'path_changed', 'unsupported_platform', 'lock_busy', 'lock_unknown',
    'destination_exists', 'deadline', 'io_error', 'rename_failed',
    'rename_unknown', 'close_unknown')
UI_ARCHIVE_BOOL_FIELDS = ('completed_archive_observed',) + tuple(
    'completed_archive_' + name for name in ARCHIVE_BOOL_FIELDS)
UI_ARCHIVE_COUNT_FIELDS = ('completed_archive_historical_entries_examined',)
UI_ARCHIVE_REASON_FIELDS = ('completed_archive_reason',)
EXTRA_UI_REASONS = ('completed_archive_observation', 'archive_refusal_cleanup_originals',
                    'filecenter_before_owner_close')
ERROR_CODES = frozenset(('fixed_path', 'fixed_ancestor', 'fixed_link', 'fixed_file',
    'fixed_identity', 'fixed_changed', 'fixed_pin', 'pins_not_frozen', 'host_recipe',
    'input_shared_changed', 'base_inventory', 'payload_budget', 'source_graph',
    'worker_interface', 'worker_policy', 'worker_archive_fields', 'bundle_pin',
    'bundle_manifest', 'filecenter_source', 'target_source_budget', 'result_fields',
    'zip_readback', 'source_assignment', 'source_literal'))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_fixed(name, pin=None, bundle=False):
    if (type(name) is not str or not name or '\\' in name or
            PurePosixPath(name).is_absolute() or re.fullmatch(r'[A-Za-z0-9_./-]+', name) is None or
            any(part in ('', '.', '..') for part in name.split('/'))):
        raise ValueError('fixed_path')
    ceiling = 4103844 if bundle else MAX_PROGRAM
    if bundle and (type(pin) is not tuple or len(pin) != 2 or pin[0] > ceiling):
        raise ValueError('bundle_pin')
    path = BASE
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or
                getattr(value, 'st_file_attributes', 0) & 0x400):
            raise ValueError('fixed_ancestor')
    for index, part in enumerate(name.split('/')):
        path = path / part
        value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise ValueError('fixed_link')
        if index < len(name.split('/')) - 1 and not stat.S_ISDIR(value.st_mode):
            raise ValueError('fixed_ancestor')
    if not stat.S_ISREG(value.st_mode) or not 0 < value.st_size <= ceiling:
        raise ValueError('fixed_file')
    before = metadata(value)
    with path.open('rb') as handle:
        opened = metadata(os.fstat(handle.fileno()))
        same = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                opened[3:6] == before[3:6]) if os.name == 'nt' else opened == before
        if not same:
            raise ValueError('fixed_identity')
        raw = handle.read(ceiling + 1)
        if metadata(os.fstat(handle.fileno())) != opened:
            raise ValueError('fixed_changed')
    if metadata(path.lstat()) != before or len(raw) != before[4]:
        raise ValueError('fixed_changed')
    if pin is not None and (len(raw), digest(raw)) != pin:
        raise ValueError('fixed_pin')
    return raw


def load_recipe(pin, name):
    raw = read_fixed(pin[0], pin[1:])
    module = types.ModuleType(name)
    module.__file__ = str(BASE / pin[0])
    # Only frozen HOST helper definitions/constants; never __main__ or graph.
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    if module.BASE != BASE:
        raise ValueError('host_recipe')
    return module, raw


def _write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise OSError('short_write')


def pin_valid(pin):
    return (type(pin) is tuple and len(pin) == 3 and type(pin[0]) is str and
            type(pin[1]) is int and 0 < pin[1] <= MAX_PROGRAM and
            type(pin[2]) is str and re.fullmatch('[0-9a-f]{64}', pin[2]) is not None)


def error_code(error):
    if (type(error) is ValueError and len(error.args) == 1 and
            type(error.args[0]) is str and error.args[0] in ERROR_CODES):
        return error.args[0]
    for cls, name in ((OSError, 'host_OSError'), (SyntaxError, 'host_SyntaxError'),
                      (TypeError, 'host_TypeError'), (KeyError, 'host_KeyError'),
                      (ValueError, 'host_ValueError'), (RuntimeError, 'host_RuntimeError')):
        if isinstance(error, cls):
            return name
    return 'host_Exception'


def exact_function(tree, name, class_name=None):
    body = tree.body
    if class_name is not None:
        classes = [node for node in body if isinstance(node, ast.ClassDef) and node.name == class_name]
        if len(classes) != 1:
            raise ValueError('worker_interface')
        body = classes[0].body
    rows = [node for node in body if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(rows) != 1:
        raise ValueError('worker_interface')
    return rows[0]


def _call_name(node, name):
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name


def _attribute_call(node, owner, name):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
            isinstance(node.func.value, ast.Name) and node.func.value.id == owner and node.func.attr == name)


def check_archive_coordinator(worker, fn, integrated):
    if integrated._assignment(worker, 'COMPLETED_ARCHIVE_BOOL_FIELDS') != ARCHIVE_BOOL_FIELDS:
        raise ValueError('worker_archive_fields')
    assignments = [node.value for node in worker.body if isinstance(node, ast.Assign) and
        any(isinstance(target, ast.Name) and target.id == 'COMPLETED_ARCHIVE_REASONS' for target in node.targets)]
    if (len(assignments) != 1 or not isinstance(assignments[0], ast.Call) or
            not isinstance(assignments[0].func, ast.Name) or assignments[0].func.id != 'frozenset' or
            assignments[0].keywords or len(assignments[0].args) != 1 or
            frozenset(ast.literal_eval(assignments[0].args[0])) != frozenset(ARCHIVE_REASONS)):
        raise ValueError('worker_archive_fields')
    coordinator = exact_function(worker, '_finish_owner_after_filecenter')
    if tuple(arg.arg for arg in coordinator.args.args) != ('component', 'ticket'):
        raise ValueError('worker_interface')
    finalizers = [node for node in ast.walk(fn) if isinstance(node, ast.Try) and node.finalbody]
    calls = [node for original in finalizers for statement in original.finalbody for node in ast.walk(statement)
             if _call_name(node, '_finish_owner_after_filecenter')]
    if (len(calls) != 1 or calls[0].keywords or
            tuple(arg.id if isinstance(arg, ast.Name) else None for arg in calls[0].args) != ('component', 'ticket') or
            any(_attribute_call(node, 'component', 'finish_owner') for node in ast.walk(fn))):
        raise ValueError('worker_policy')
    body = coordinator.body[1:] if (isinstance(coordinator.body[0], ast.Expr) and
        isinstance(coordinator.body[0].value, ast.Constant) and type(coordinator.body[0].value.value) is str) else coordinator.body
    # Actual passive borrower checks guard the direct rejection before the sole
    # active finish_owner call. Cached close results alone cannot reach it.
    if (len(body) != 5 or not isinstance(body[1], ast.Assign) or
            len(body[1].targets) != 1 or not isinstance(body[1].targets[0], ast.Name) or
            body[1].targets[0].id != 'allowed' or not isinstance(body[2], ast.If) or
            body[2].orelse or len(body[2].body) != 1 or not isinstance(body[2].body[0], ast.Try) or
            not isinstance(body[3], ast.If) or not isinstance(body[3].test, ast.UnaryOp) or
            not isinstance(body[3].test.op, ast.Not) or
            not isinstance(body[3].test.operand, ast.Name) or body[3].test.operand.id != 'allowed' or
            body[3].orelse or len(body[3].body) != 2 or
            not isinstance(body[3].body[0], ast.Expr) or not _call_name(body[3].body[0].value, '_reject_archive_cleanup') or
            len(body[3].body[0].value.args) != 1 or
            not isinstance(body[3].body[0].value.args[0], ast.Name) or body[3].body[0].value.args[0].id != 'component' or
            not isinstance(body[3].body[1], ast.Expr) or not _call_name(body[3].body[1].value, 'need') or
            len(body[3].body[1].value.args) != 2 or
            not isinstance(body[3].body[1].value.args[0], ast.Constant) or body[3].body[1].value.args[0].value is not False or
            not isinstance(body[3].body[1].value.args[1], ast.Constant) or
            body[3].body[1].value.args[1].value != 'filecenter_before_owner_close' or
            not isinstance(body[4], ast.Expr) or not _attribute_call(body[4].value, 'component', 'finish_owner')):
        raise ValueError('worker_policy')
    passive = body[2].body[0]
    if (len(passive.body) != 1 or not isinstance(passive.body[0], ast.Assign) or
            len(passive.body[0].targets) != 1 or not isinstance(passive.body[0].targets[0], ast.Name) or
            passive.body[0].targets[0].id != 'allowed' or not isinstance(passive.body[0].value, ast.BoolOp) or
            not isinstance(passive.body[0].value.op, ast.And) or
            ast.dump(body[1].value) != ast.dump(ast.parse('ticket is None', mode='eval').body) or
            ast.dump(body[2].test) != ast.dump(ast.parse('ticket is not None', mode='eval').body)):
        raise ValueError('worker_policy')
    current_checks = {ast.dump(value) for value in passive.body[0].value.values}
    for expression in ('_filecenter_current(component, ticket) is True',
                       "ticket['closed_creator'](ticket['companion']) is True",
                       "ticket['audio_guardian'].settled() is True"):
        if ast.dump(ast.parse(expression, mode='eval').body) not in current_checks:
            raise ValueError('worker_policy')
    if (len([node for node in ast.walk(coordinator) if _attribute_call(node, 'component', 'finish_owner')]) != 1 or
            any(_attribute_call(node, 'owner', 'close') for node in ast.walk(exact_function(worker, '_reject_archive_cleanup')))):
        raise ValueError('worker_policy')
    projection = exact_function(worker, '_copy_completed_archive_facts')
    if (tuple(arg.arg for arg in projection.args.args) != ('component', 'facts') or
            any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
                node.func.attr == 'completed_archive_facts' for node in ast.walk(projection))):
        raise ValueError('worker_archive_fields')
    projection_calls = [node for original in finalizers for statement in original.finalbody for node in ast.walk(statement)
                        if _call_name(node, '_copy_completed_archive_facts')]
    if (len(projection_calls) != 1 or projection_calls[0].keywords or
            tuple(arg.id if isinstance(arg, ast.Name) else None for arg in projection_calls[0].args) != ('component', 'facts')):
        raise ValueError('worker_archive_fields')


def check_worker(integrated, filecenter, inputs):
    worker = ast.parse(inputs[WORKER[0]].decode('utf-8'), feature_version=(3, 5))
    # This frozen runner interface is read, not imported or executed.
    runner = ast.parse(inputs[integrated.RUNNER[0]].decode('utf-8'), feature_version=(3, 5))
    constructor = exact_function(runner, '__init__', 'FixedSession')
    if (tuple(arg.arg for arg in constructor.args.args) !=
            ('self', 'artifacts', 'preflight_only', 'receive_trial_requested', 'profile',
             'archive_completed_receives') or constructor.args.vararg is not None or
            constructor.args.kwarg is not None or constructor.args.kwonlyargs or
            len(constructor.args.defaults) != 3 or
            not isinstance(constructor.args.defaults[0], ast.Constant) or
            constructor.args.defaults[0].value is not False or
            not isinstance(constructor.args.defaults[1], ast.Constant) or
            constructor.args.defaults[1].value != 'diagnostic' or
            not isinstance(constructor.args.defaults[2], ast.Constant) or
            constructor.args.defaults[2].value is not False):
        raise ValueError('worker_interface')
    fn = exact_function(worker, 'run_fixed')
    if (tuple(arg.arg for arg in fn.args.args) !=
            ('runner_raw', 'artifacts', 'validator_raw', 'filecenter_sources') or
            fn.args.defaults or fn.args.vararg is not None or fn.args.kwarg is not None or fn.args.kwonlyargs):
        raise ValueError('worker_interface')
    creators = [node for node in ast.walk(fn) if isinstance(node, ast.Call) and
        isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and
        node.func.value.id == 'runner' and node.func.attr == 'FixedSession']
    if len(creators) != 1:
        raise ValueError('worker_policy')
    call = creators[0]
    keywords = {value.arg: value.value for value in call.keywords}
    if (len(call.args) != 2 or len(call.keywords) != 3 or
            not isinstance(call.args[0], ast.Name) or call.args[0].id != 'artifacts' or
            not isinstance(call.args[1], ast.Constant) or call.args[1].value is not False or
            set(keywords) != {'receive_trial_requested', 'profile', 'archive_completed_receives'} or
            not isinstance(keywords['receive_trial_requested'], ast.Constant) or
            keywords['receive_trial_requested'].value is not True or
            not isinstance(keywords['archive_completed_receives'], ast.Constant) or
            keywords['archive_completed_receives'].value is not True or
            not isinstance(keywords['profile'], ast.Name) or keywords['profile'].id != 'INTERACTIVE_PROFILE'):
        raise ValueError('worker_policy')
    assignment = integrated._assignment
    if not all((
        assignment(worker, 'RUNNER_PIN') == integrated.RUNNER[1:],
        assignment(worker, 'STATE_ROOT') == integrated.STATE_ROOT,
        assignment(worker, 'STATE_ALIAS') == integrated.STATE_ALIAS,
        assignment(worker, 'MONITOR_PIN') == (integrated.MONITOR[0], integrated.MONITOR[2], integrated.MONITOR[3]),
        assignment(worker, 'VALIDATOR_PIN') == filecenter.VALIDATOR[1:],
        assignment(worker, 'SESSION') == filecenter.BUNDLE_SESSION,
        assignment(worker, 'FILECENTER_PINS') == tuple((n, s, h) for n, p, s, h in filecenter.FILECENTER_SOURCES),
        assignment(worker, 'TRIAL_BOOL_FIELDS') == integrated.TRIAL_BOOL_FIELDS,
        assignment(worker, 'INTERACTIVE_PROFILE') == 'receive-interactive-v1',
        assignment(worker, 'INTERACTIVE_SECONDS') == 600.0,
        assignment(worker, 'EXIT_MARGIN_SECONDS') == 1.0,
    )):
        raise ValueError('source_graph')
    initializers = []
    for node in ast.walk(fn):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
                isinstance(node.func.value, ast.Name) and node.func.value.id == 'facts' and node.func.attr == 'update'):
            values = {keyword.arg: keyword.value for keyword in node.keywords}
            if 'auto_receive_action_issued' in values:
                initializers.append(values)
    if (len(initializers) != 1 or
            not isinstance(initializers[0].get('receive_trial_policy_requested'), ast.Constant) or
            initializers[0]['receive_trial_policy_requested'].value is not True or
            not isinstance(initializers[0].get('auto_receive_action_issued'), ast.Constant) or
            initializers[0]['auto_receive_action_issued'].value is not False):
        raise ValueError('worker_policy')
    check_archive_coordinator(worker, fn, integrated)
    return worker, runner


def make_ui(integrated, filecenter, checker, inputs, payload):
    modules = tuple(sorted(set(integrated.MODULE_NAMES + integrated.PRIVATE_MODULE_NAMES +
        tuple(row[0] for row in filecenter.FILECENTER_SOURCES) + (
            'fixed_formal_ui_session', 'fixed_formal_ui_runner', 'fixed_formal_ui_assets',
            'fixed_formal_receive_monitor', 'startup_readonly_private_owner',
            'threading', 'socket', 'subprocess', 'types'))))
    reasons = tuple(dict.fromkeys(filecenter.UI_REASONS + EXTRA_UI_REASONS + ARCHIVE_REASONS))
    lines = ['USE_UI=True', 'ARCHIVE_POLICY=True', 'ERROR_MODULES=(']
    lines.extend('    ' + repr(name) + ',' for name in modules)
    lines.extend((')', 'RESULT_REASONS=('))
    lines.extend('    ' + repr(name) + ',' for name in reasons)
    lines.append(')')
    for tag, pin in (('RUNNER', integrated.RUNNER), ('WORKER', WORKER), ('VALIDATOR', filecenter.VALIDATOR)):
        lines.append(tag + '_PIN=' + repr(pin[1:]))
        lines.extend((tag + '_ENCODED=(', integrated._short_chunks(checker, inputs[pin[0]]), ')'))
    lines.append('ARTIFACT_ROWS=(')
    for name, path, size, sha in payload:
        lines.extend(('    (' + repr(name) + ',' + str(size) + ',' + repr(sha) + ',(',
                      integrated._short_chunks(checker, inputs[path]), '    )),'))
    lines.extend((')', 'FILECENTER_PINS=('))
    for name, path, size, sha in filecenter.FILECENTER_SOURCES:
        lines.append('    ' + repr((name, size, sha)) + ',')
    lines.extend((')', 'FILECENTER_ROWS=('))
    for name, path, size, sha in filecenter.FILECENTER_SOURCES:
        lines.extend(('    (' + repr(name) + ',' + str(size) + ',' + repr(sha) + ',(',
                      integrated._short_chunks(checker, inputs[path]), '    )),'))
    lines.append(')')
    common = integrated.TARGET_COMMON.replace('compressed=base64.b64decode(encoded)',
                                              'compressed=base64.b64decode(encoded,validate=True)')
    common = common.replace('artifacts=tuple(', """if (len(ARTIFACT_ROWS)!=76 or len(set(row[0] for row in ARTIFACT_ROWS))!=76 or
    sum(row[1] for row in ARTIFACT_ROWS)>4194304):raise ValueError('payload_budget')
artifacts=tuple(""")
    raw = ('\n'.join(lines) + '\n' + common + filecenter.TARGET_UI).encode('ascii')
    check_budget(raw)
    return raw


def check_budget(raw):
    if type(raw) is not bytes or len(raw) > MAX_PROGRAM or any(len(line) > 256 for line in raw.splitlines()):
        raise ValueError('target_source_budget')


def check_envelopes(integrated, filecenter, trees, payload):
    expected = tuple((name, size, sha) for name, path, size, sha in payload)
    for tag, tree in trees.items():
        if (integrated._assignment(tree, 'RUNNER_PIN') != integrated.RUNNER[1:] or
                integrated._assignment(tree, 'USE_UI') is not (tag == 'ui')):
            raise ValueError('source_graph')
        rows = integrated._assignment(tree, 'ARTIFACT_ROWS')
        if len(rows) != 76 or tuple(row[:3] for row in rows) != expected:
            raise ValueError('source_graph')
    if (integrated._assignment(trees['ui'], 'WORKER_PIN') != WORKER[1:] or
            integrated._assignment(trees['ui'], 'VALIDATOR_PIN') != filecenter.VALIDATOR[1:] or
            integrated._assignment(trees['ui'], 'ARCHIVE_POLICY') is not True):
        raise ValueError('source_graph')
    for tag, policy in (('default-service', False), ('enabled-service', True)):
        tree = trees[tag]
        if integrated._assignment(tree, 'ARCHIVE_POLICY') is not policy:
            raise ValueError('source_graph')
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and
            isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and
            node.func.value.id == 'session' and node.func.attr == 'run_fixed']
        if len(calls) != 1 or len(calls[0].args) != 2 or len(calls[0].keywords) != 2:
            raise ValueError('source_graph')
        keys = {node.arg: node.value for node in calls[0].keywords}
        if (set(keys) != {'receive_trial_requested', 'archive_completed_receives'} or
                any(not isinstance(value, ast.Name) or value.id != 'ARCHIVE_POLICY' for value in keys.values())):
            raise ValueError('source_graph')
        if not filecenter._filecenter_envelope_literals(trees['ui'], tree):
            raise ValueError('source_graph')


def ui_schema(filecenter):
    return (filecenter.UI_BOOL_FIELDS + UI_ARCHIVE_BOOL_FIELDS,
            filecenter.UI_COUNT_FIELDS + UI_ARCHIVE_COUNT_FIELDS,
            filecenter.UI_REASON_FIELDS + UI_ARCHIVE_REASON_FIELDS,
            tuple(dict.fromkeys(filecenter.UI_REASONS + EXTRA_UI_REASONS)))


def parse_ui_result(raw, filecenter):
    """Strict future-result parser only; main never invokes a target program."""
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    lines = derived.splitlines()
    remote = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M)
    rows = [line[7:] for line in lines if line.startswith('RESULT=')]
    if len(remote) != 1 or lines.count('MTA_REMOTE_OK') != 1 or len(rows) != 1:
        raise ValueError('result_fields')
    value = ast.literal_eval(rows[0])
    bools, counts, reasons, enums = ui_schema(filecenter)
    if (type(value) is not dict or set(value) != frozenset(bools + counts + reasons) or
            any(type(value[key]) is not bool for key in bools) or
            any(type(value[key]) is not int or not 0 <= value[key] <= 512 for key in counts) or
            type(value['reason']) is not str or value['reason'] not in enums or
            any(type(value[key]) is not str or value[key] not in filecenter.TRIAL_REASONS
                for key in filecenter.UI_REASON_FIELDS[1:]) or
            type(value['completed_archive_reason']) is not str or value['completed_archive_reason'] not in ARCHIVE_REASONS or
            value['completed_archive_historical_entries_examined'] != 0 or
            value['completed_archive_native_restore_grant'] is not False or
            value['completed_archive_receive_admission'] is not False or
            value['receive_trial_policy_requested'] is not True or
            value['auto_receive_action_issued'] is not False or
            value['interactive_window_requested'] is not True or
            value['receive_trial_claim_count'] not in (0, 1) or
            value['receive_trial_claimed'] is not (value['receive_trial_claim_count'] == 1) or
            value['receive_trial_session_attached'] and not value['receive_trial_claimed'] or
            value['completed_archive_requested'] is not True):
        raise ValueError('result_fields')
    if (value['completed_archive_archived'] and
            not (value['completed_archive_observed'] and value['completed_archive_attempted'] and
                 value['completed_archive_rename_called'] and value['completed_archive_rename_outcome_known']) or
            value['completed_archive_archive_outcome_unknown'] and value['completed_archive_rename_outcome_known'] or
            value['completed_archive_observed'] and value['completed_archive_archive_outcome_unknown'] is not
                (value['completed_archive_rename_called'] and not value['completed_archive_rename_outcome_known'])):
        raise ValueError('result_fields')
    ready = lines.count('MTA_FORMAL_UI_READY')
    if (ready not in (0, 1) or ready == 1 and not (value['ui_ready'] and value['credentials_removed']) or
            value['complete'] and (ready != 1 or not value['completed_archive_observed'] or
                not value['completed_archive_resources_closed'] or value['resource_pending'])):
        raise ValueError('result_fields')
    return int(remote[0]), value


def main():
    if len(sys.argv) != 1:
        print('PC SOURCE only: no device/UI/archive arguments')
        return 2
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
    out = BASE / 'results' / ('receive-filecenter-archive-v1-source-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    inputs, programs, trees = {}, {}, {}
    expected_paths = base_paths = None
    report = dict(schema='p011-receive-filecenter-archive-v1-source', mode='source', passed=False,
        source_check_complete=False, source_preserved=False, source_count=0, base_input_count=0,
        base_inventory_verified=False, integrated_graph_byte_reused=False, business_graph_executed=False,
        payload_role_count=0, payload_raw_bytes=0, payload_raw_limit=MAX_GRAPH_RAW,
        ui_program_bytes=0, default_service_program_bytes=0, enabled_service_program_bytes=0,
        program_byte_limit=MAX_PROGRAM, physical_line_limit=256,
        new_worker_ast_count=0, runner_interface_ast_count=0, old_graph_role_ast_count=0,
        envelope_ast_count=0, host_error_code=None, old_test_methods=0, old_http_smoke_replayed=False,
        device_invoked=False, ui_started=False, native_started=False, receive_action_issued=False,
        send_action_issued=False, auto_receive_action_issued=False, archive_action_executed=False,
        archive_policy_source_fixed=True, ui_trial_policy_source_fixed=True,
        ui_constructor_source_crosschecked=False, ui_archive_projection_source_crosschecked=False,
        ui_archive_close_coordinator_source_crosschecked=False, production_archive_consumer_tested=False,
        old_client_history_examined=False, historical_entries_examined=0, pending_removed=False,
        vendor_binary_replaced=False, native_restore_grant=False, receive_admission=False,
        phone_tested=False, full_network_restore_verified=False, physical_ui_verified=False,
        whole_system_zero_rf_claimed=False, filecenter_source_count=9,
        filecenter_source_bytes=EXPECTED_FILECENTER_RAW, filecenter_source_cap=MAX_FILECENTER_RAW,
        filecenter_ui_single_copy=False, filecenter_service_payload_count=0,
        bundle_asset_count=EXPECTED_BUNDLE_COUNT, bundle_raw_bytes=EXPECTED_BUNDLE_RAW,
        bundle_crosschecked=False, bundle_staged=False)
    try:
        integrated, integrated_raw = load_recipe(INTEGRATED, 'fixed_integrated_archive_host_recipe')
        filecenter, filecenter_raw = load_recipe(FILECENTER, 'fixed_filecenter_host_recipe')
        checker, checker_raw = integrated.load_checker()
        def retain(path, raw):
            if path in inputs:
                if inputs[path] != raw:
                    raise ValueError('input_shared_changed')
                return
            inputs[path] = raw
            target = out / 'private-inputs' / path
            target.parent.mkdir(parents=True, exist_ok=True)
            _write_new(target, raw)
        retain(INTEGRATED[0], integrated_raw)
        retain(integrated.CHECKER[0], checker_raw)
        fixed = (integrated.MANIFEST, integrated.PRIVATE_MANIFEST, integrated.RUNNER,
                 integrated.TRANSPORT) + integrated.CMDS
        if not all(pin_valid(pin) for pin in fixed + (WORKER, filecenter.VALIDATOR)):
            raise ValueError('pins_not_frozen')
        for path, size, sha in fixed:
            retain(path, read_fixed(path, (size, sha)))
        rows = integrated.manifest_rows(inputs[integrated.MANIFEST[0]])
        private_rows = integrated.manifest_rows(inputs[integrated.PRIVATE_MANIFEST[0]], private=True)
        payload = rows + integrated.HELPERS + private_rows + (integrated.WPA, integrated.MONITOR)
        if (len(rows) != 36 or len(private_rows) != 35 or len(payload) != EXPECTED_GRAPH_COUNT or
                len({row[0] for row in payload}) != len(payload) or
                sum(row[2] for row in payload) > MAX_GRAPH_RAW):
            raise ValueError('payload_budget')
        for name, path, size, sha in payload:
            retain(path, read_fixed(path, (size, sha)))
        base_paths = {INTEGRATED[0], integrated.CHECKER[0]} | {pin[0] for pin in fixed} | {row[1] for row in payload}
        if len(base_paths) != EXPECTED_BASE_INPUTS or set(inputs) != base_paths:
            raise ValueError('base_inventory')
        report.update(base_input_count=len(base_paths), base_inventory_verified=True,
                      integrated_graph_byte_reused=True, payload_role_count=len(payload),
                      payload_raw_bytes=sum(row[2] for row in payload))
        retain(FILECENTER[0], filecenter_raw)
        retain(filecenter.VALIDATOR[0], read_fixed(filecenter.VALIDATOR[0], filecenter.VALIDATOR[1:]))
        retain(WORKER[0], read_fixed(WORKER[0], WORKER[1:]))
        if (len(filecenter.FILECENTER_SOURCES) != 9 or
                len({row[0] for row in filecenter.FILECENTER_SOURCES}) != 9 or
                sum(row[2] for row in filecenter.FILECENTER_SOURCES) != EXPECTED_FILECENTER_RAW or
                filecenter.FILECENTER_SOURCE_BYTES != EXPECTED_FILECENTER_RAW or
                filecenter.FILECENTER_SOURCE_CAP != MAX_FILECENTER_RAW or
                EXPECTED_FILECENTER_RAW > MAX_FILECENTER_RAW or
                tuple(integrated.ARCHIVE_BOOL_FIELDS) != ARCHIVE_BOOL_FIELDS or
                tuple(integrated.ARCHIVE_REASONS) != ARCHIVE_REASONS):
            raise ValueError('filecenter_source')
        for name, path, size, sha in filecenter.FILECENTER_SOURCES:
            retain(path, read_fixed(path, (size, sha)))
        bundle_pins = {filecenter.BUNDLE + '/' + name: (size, sha) for name, size, sha in filecenter.BUNDLE_PINS}
        if (len(bundle_pins) != EXPECTED_BUNDLE_COUNT or
                sum(pin[0] for pin in bundle_pins.values()) != EXPECTED_BUNDLE_RAW or
                EXPECTED_BUNDLE_RAW > MAX_GRAPH_RAW):
            raise ValueError('bundle_pin')
        for path, pin in bundle_pins.items():
            retain(path, read_fixed(path, pin, bundle=True))
        manifest_bytes = ''.join(sha + ' ' + str(size) + ' ' + name + '\n'
            for name, size, sha in filecenter.BUNDLE_PAYLOAD_PINS).encode('ascii')
        if inputs[filecenter.BUNDLE + '/SOURCE.sha256'] != manifest_bytes:
            raise ValueError('bundle_manifest')
        retain(SELF, read_fixed(SELF))
        retain(CMD, read_fixed(CMD))
        expected_paths = base_paths | {FILECENTER[0], WORKER[0], filecenter.VALIDATOR[0], SELF, CMD} | \
            {row[1] for row in filecenter.FILECENTER_SOURCES} | set(bundle_pins)
        if set(inputs) != expected_paths:
            raise ValueError('source_graph')
        _write_new(out / 'private-inputs.json', (json.dumps(
            {path: dict(bytes=len(raw), sha256=digest(raw)) for path, raw in inputs.items()},
            sort_keys=True, indent=2) + '\n').encode('ascii'))
        worker, runner = check_worker(integrated, filecenter, inputs)
        report.update(new_worker_ast_count=1, runner_interface_ast_count=1,
                      ui_constructor_source_crosschecked=True, ui_archive_projection_source_crosschecked=True,
                      ui_archive_close_coordinator_source_crosschecked=True, bundle_crosschecked=True)
        programs['ui'] = make_ui(integrated, filecenter, checker, inputs, payload)
        for policy, tag in ((False, 'default-service'), (True, 'enabled-service')):
            programs[tag] = integrated.make_source(checker, inputs, payload, policy)
        for tag, raw in programs.items():
            check_budget(raw)
            trees[tag] = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
            _write_new(out / ('private-target-' + tag + '.py'), raw)
            report[tag.replace('-', '_') + '_program_bytes'] = len(raw)
            report[tag.replace('-', '_') + '_program_sha256'] = digest(raw)
        check_envelopes(integrated, filecenter, trees, payload)
        report.update(filecenter_ui_single_copy=True, envelope_ast_count=len(trees),
                      source_check_complete=True)
    except BaseException as error:
        report['host_error_code'] = error_code(error)
    finally:
        preserved = expected_paths is not None and set(inputs) == expected_paths
        for path, original in inputs.items():
            try:
                pin = bundle_pins.get(path) if 'bundle_pins' in locals() else None
                if (read_fixed(path, pin, bundle=pin is not None) != original or
                        (out / 'private-inputs' / path).read_bytes() != original):
                    preserved = False
            except BaseException:
                preserved = False
        if len(programs) != 3:
            preserved = False
        for tag, original in programs.items():
            try:
                if (out / ('private-target-' + tag + '.py')).read_bytes() != original:
                    preserved = False
            except BaseException:
                preserved = False
        report['source_count'], report['source_preserved'] = len(inputs), preserved
    report['passed'] = (report['host_error_code'] is None and report['source_check_complete'] and
                        report['source_preserved'] and report['base_inventory_verified'])
    if any(type(value) not in (type(None), bool, int, str) for value in report.values()):
        raise ValueError('result_fields')
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (
        b'PC SOURCE-only new FileCenter UI/completed archive composition. No target program or business graph executes here. '
        b'Frozen integrated 74 inputs/36 ordinary/34 Boot/35 private/76 graph payload are byte reused. '
        b'Raw graph4MiB/program2MiB/line256 stay fixed; exact FileCenter9 raw91295 has its separate131072 cap and one UI-only copy. '
        b'GUI b6 original19 assets/raw4182249 and fixed validator are readback snapshots only, never staged by this entry. '
        b'The UI source calls the original four-argument worker; its six-name FixedSession constructor uses the three fixed '
        b'keywords trial=True/profile=original600-second interactive/archive=True. Service sources select the original False/True '
        b'trusted policy recipes; no browser policy or automatic receive action exists. New UI archive facts are strict scalar '
        b'projections, not proof of receipt, Native restoration, completed archive or phone acceptance. No old test/smoke or '
        b'CLIENT history is replayed, scanned, parsed, cleared or repaired. The program guards preserved partial/conflict inventories; '
        b'SOURCE success cannot validate target IO or closure. No device executor/ADB/UI-start switch is implemented. '
        b'Original startup/task300/Factory120/cleanup60/guardian68+135/interactive600 bounds are not renewed. All source/artifact '
        b'bytes, generated target programs and inventories remain private; public ZIP is exactly this scalar result and README.\n')
    _write_new(out / 'result.json', public)
    _write_new(out / 'README.txt', readme)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as handle:
        handle.writestr('result.json', public)
        handle.writestr('README.txt', readme)
    with zipfile.ZipFile(archive) as handle:
        if (handle.namelist() != ['result.json', 'README.txt'] or handle.testzip() is not None or
                handle.read('result.json') != public or handle.read('README.txt') != readme):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], mode='source', result_dir=str(out),
        result_zip=str(archive), zip_sha256=digest(archive.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
