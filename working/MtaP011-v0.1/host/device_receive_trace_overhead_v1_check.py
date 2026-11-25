"""Default SOURCE; explicit --check-device runs a bounded P011 trace-cost model.

The frozen real TraceOwner is unchanged. Ordinary selected-check/2000-row
dictionary-generator fixtures are NOT actual Handoff/Trial/Owner lifecycles.
No staging, radio mutation, UI, phone, graph or old test/main invocation.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import traceback
import types
import uuid
import zlib

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_trace_overhead_v1_check.py'
CMD = 'DEVICE_MTA_RECEIVE_TRACE_OVERHEAD_V1_CHECK.cmd'
PINS = (
    ('host/host_artifact_seal_v1.py', 6784,
     '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7'),
    ('host/device_probe.py', 8759,
     'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348'),
    ('host/device_filecenter_audio_deadline_v1_check.py', 13753,
     '69f7c6d4b192f1ab7a7c75101a6583d31773141e007b7f33c5ba2e457763d71c'),
    ('host/receive_trace_overhead_v1_check.py', 20067,
     '83bfb37972c97eb15fa6c441e32aca9328eec0ea6bb36d25fb711d870ed918ac'),
    ('candidate/receive-handoff-trace-v1/runtime/handoff_trace.py', 14820,
     '990cbf387893706e263abc43aa4fdc728782c4a0a88de531d5a1a53274862657'))
SCHEMA = 'p011-receive-trace-overhead-v1-device-model'
ORDER = ('none', 'actual_trace', 'actual_trace', 'none')
LEDGER_ROWS = 2000
CALLS_PER_BLOCK = 4
GROUPS = 4
CALL_COUNT = 64
BLOCK_CAP = 3.0
MODEL_BUDGET = 25.0
ALARM = 30
HOST_TIMEOUT = 45
TARGET_LIMIT = 48000
TARGET_MAX_LINE = 256
OUTPUT_LIMIT = 65536

# Only finite mechanical differences from the frozen HOST block. The receipt
# sink retains a failed block's actual flags; it does not affect the timed loop.
BLOCK_EDITS = (
    ('global_until):', 'global_until, receipts):'),
    ('wall_seconds=None, process_cpu_seconds=None, thread_cpu_seconds=None,',
     'wall_seconds=None, process_cpu_seconds=None,'),
    ('    expected = LEDGER_ROWS * (LEDGER_ROWS - 1) // 2',
     '    receipts.append(row)\n    expected = LEDGER_ROWS * (LEDGER_ROWS - 1) // 2'),
    ('wall, cpu, thread_cpu = time.perf_counter(), time.process_time(), time.thread_time()',
     'wall, cpu = time.perf_counter(), time.process_time()'),
    ("            row['thread_cpu_seconds'] = time.thread_time() - thread_cpu\n", ''),
    ('host-trace-overhead-block', 'device-trace-overhead-block'))

REMOTE_RUN = r'''
def model_run():
    started = time.monotonic()
    report = dict(schema=SCHEMA, passed=False, blocks=[], error=None,
        modules_restored=False, hooks_restored=False, all_threads_joined=False,
        owned_fixture_namespaces_cleared=False, trace_namespace_cleared=False,
        python_version=tuple(sys.version_info[:3]), ledger_rows=LEDGER_ROWS,
        calls_per_block=CALLS_PER_BLOCK, groups=GROUPS, call_count=CALL_COUNT,
        thread_cpu_collected=False, trace_source_verified=False)
    registered, previous, missing = {}, {}, object()
    trace = phone = modules = trial = ledger = check = None
    owned = []
    try:
        need(os.geteuid() == 0 and os.uname()[4] == 'armv7l', 'target_profile')
        need(tuple(sys.version_info[:3]) == (3, 5, 5), 'target_python')
        need(sys.gettrace() is None and getattr(threading, '_trace_hook', object()) is None,
             'existing_hook')
        raw = zlib.decompress(base64.b64decode(TRACE_PACKED))
        need(len(raw) == TRACE_BYTES and hashlib.sha256(raw).hexdigest() == TRACE_SHA256, 'trace_pin')
        trace = types.ModuleType('device_trace_overhead_frozen_trace_v1')
        exec(compile(raw, '<frozen-actual-trace-v1>', 'exec'), trace.__dict__)
        report['trace_source_verified'] = True
        phone, modules, trial, ledger, check = fixture(trace)
        owned = list(modules.values()) + [trial, phone]
        registered = dict(modules)
        registered[TRIAL_ROLE] = trial
        for role, module in registered.items():
            previous[role] = sys.modules.get(role, missing)
            sys.modules[role] = module
        until = started + WORKER_BUDGET
        for group in range(GROUPS):
            for slot, mode in enumerate(ORDER):
                need(time.monotonic() < until, 'worker_deadline')
                block(trace, phone, ledger, check, group, slot, mode, until, report['blocks'])
    except BaseException as error:
        report['error'] = error_code(error)
    finally:
        report['hooks_restored'] = (sys.gettrace() is None and
            getattr(threading, '_trace_hook', object()) is None)
        report['all_threads_joined'] = not any(
            thread.name == 'device-trace-overhead-block' for thread in threading.enumerate())
        # A timed-out daemon is NOT drained. Leave its namespaces/aliases intact
        # and report FAIL; this isolated process still has its original alarm.
        if report['all_threads_joined'] and report['hooks_restored']:
            unchanged = all(sys.modules.get(role) is module for role, module in registered.items())
            for role in registered:
                if sys.modules.get(role) is registered[role]:
                    if previous[role] is missing:
                        del sys.modules[role]
                    else:
                        sys.modules[role] = previous[role]
            report['modules_restored'] = unchanged and all(
                sys.modules.get(role, missing) is previous[role] for role in registered)
            if report['modules_restored']:
                # Only self-created ModuleType dictionaries; NEVER stdlib or
                # saved original modules. No worker can still use these refs.
                phone = modules = trial = ledger = check = None
                for module in owned:
                    module.__dict__.clear()
                report['owned_fixture_namespaces_cleared'] = (len(owned) == 6 and
                    all(module.__dict__ == {} for module in owned))
                owned = []
                registered = {}
                if trace is not None:
                    trace.__dict__.clear()
                    report['trace_namespace_cleared'] = trace.__dict__ == {}
                    trace = None
        report['elapsed_seconds'] = time.monotonic() - started
    report['blocks'] = tuple(report['blocks'])
    report['passed'] = (report['error'] is None and len(report['blocks']) == GROUPS * len(ORDER) and
        report['trace_source_verified'] and report['modules_restored'] and report['hooks_restored'] and
        report['all_threads_joined'] and report['owned_fixture_namespaces_cleared'] and
        report['trace_namespace_cleared'] and report['elapsed_seconds'] <= WORKER_BUDGET)
    output = 'TRACE_OVERHEAD_MODEL=' + repr(report)
    if len(output.encode('ascii')) > OUTPUT_LIMIT:
        raise ValueError('output_limit')
    print(output, flush=True)
    return 0 if report['passed'] else 1

raise SystemExit(model_run())
'''


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def definitions(key, raw):
    module = types.ModuleType('_device_trace_overhead_' + Path(key).stem)
    module.__file__ = str(BASE / key)
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def make_target(model_raw, trace_raw):
    need((len(model_raw), digest(model_raw)) == PINS[3][1:], 'model_pin')
    need((len(trace_raw), digest(trace_raw)) == PINS[4][1:], 'trace_pin')
    text = model_raw.decode('ascii').replace('\r\n', '\n')
    tree = ast.parse(text)
    wanted = ('need', 'error_code', 'fixture', 'after_restore', 'block')
    functions = {}
    literals = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted:
            need(node.name not in functions, 'duplicate_function')
            functions[node.name] = ast.get_source_segment(text, node) + '\n'
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in ('TRIAL_FIXTURE', 'SELECTED_FIXTURE', 'KNOWN_ERRORS', 'TRIAL_ROLE'):
                need(name not in literals, 'duplicate_literal')
                literals[name] = ast.literal_eval(node.value)
    need(tuple(functions) == wanted and set(literals) ==
         {'TRIAL_FIXTURE', 'SELECTED_FIXTURE', 'KNOWN_ERRORS', 'TRIAL_ROLE'}, 'model_fragments')
    need(literals['TRIAL_ROLE'] == 'mta_receive_trial' and
         len(literals['SELECTED_FIXTURE'].splitlines()) == 3, 'model_fixture')
    original = functions['block']
    revised = original
    for old, new in BLOCK_EDITS:
        need(revised.count(old) == 1, 'block_edit_anchor')
        revised = revised.replace(old, new, 1)
    inverse = revised
    for old, new in reversed(BLOCK_EDITS):
        if new:
            need(inverse.count(new) == 1, 'block_inverse_anchor')
            inverse = inverse.replace(new, old, 1)
        else:
            anchor = "            row['process_cpu_seconds'] = time.process_time() - cpu\n"
            need(inverse.count(anchor) == 1, 'block_inverse_anchor')
            inverse = inverse.replace(anchor, old + anchor, 1)
    need(inverse == original, 'block_inverse')
    functions['block'] = revised
    packed = base64.b64encode(zlib.compress(trace_raw)).decode('ascii')
    prefix = ('import base64,hashlib,os,sys,threading,time,types,zlib\n' +
        'SCHEMA=' + repr(SCHEMA) + '\nLEDGER_ROWS=2000\nCALLS_PER_BLOCK=4\nGROUPS=4\nCALL_COUNT=64\n' +
        'ORDER=' + repr(ORDER) + '\nBLOCK_JOIN_CAP=3.0\nWORKER_BUDGET=25.0\nOUTPUT_LIMIT=65536\n' +
        'TRACE_BYTES=' + repr(len(trace_raw)) + '\nTRACE_SHA256=' + repr(digest(trace_raw)) + '\n')
    for name in ('KNOWN_ERRORS', 'TRIAL_ROLE', 'TRIAL_FIXTURE', 'SELECTED_FIXTURE'):
        value = repr(literals[name])
        if len(name + '=' + value) <= TARGET_MAX_LINE:
            prefix += name + '=' + value + '\n'
        else:
            if type(literals[name]) is str:
                prefix += name + '=(\n' + ''.join(repr(part) + '\n' for part in
                    literals[name].splitlines(keepends=True)) + ')\n'
            else:
                need(type(literals[name]) is tuple, 'literal_line_budget')
                prefix += name + '=(\n' + ''.join(repr(part) + ',\n' for part in
                    literals[name]) + ')\n'
    prefix += 'TRACE_PACKED=(\n' + ''.join(repr(packed[index:index + 76]) + '\n'
        for index in range(0, len(packed), 76)) + ')\n'
    target = (prefix + '\n'.join(functions[name] for name in wanted) + REMOTE_RUN).encode('ascii')
    ast.parse(target.decode('ascii'), feature_version=(3, 5))
    need(len(target) <= TARGET_LIMIT and max(map(len, target.splitlines())) <= TARGET_MAX_LINE,
         'target_budget')
    need(b'thread_time' not in target and b'import json' not in target and b'pathlib' not in target,
         'target_dependency')
    return target, dict(unchanged_functions=list(wanted[:-1]), block_edits=len(BLOCK_EDITS),
        block_inverse_exact=True, fixture_literals_unchanged=True,
        host_module_not_imported=True, old_main_called=False,
        production_trace_bytes_unchanged=True, production_trace_methods_replaced=False)


def finite(value, limit):
    return type(value) is float and math.isfinite(value) and 0.0 <= value <= limit


def trace_events(value):
    if type(value) is not tuple or len(value) > 24:
        return False
    for row in value:
        if (type(row) is not dict or set(row) != {'kind', 'code', 'module', 'function', 'line'} or
                row['kind'] not in ('HandoffError', 'ProtocolError', 'RadioObservationError',
                    'ValueError', 'TypeError', 'UnicodeError', 'UnicodeDecodeError',
                    'UnicodeEncodeError', 'RuntimeError', 'OverflowError', 'OtherError') or
                not (row['code'] is None or (type(row['code']) is str and row['code'].isascii() and
                    row['code'].isidentifier() and len(row['code']) <= 64)) or
                row['module'] != 'mta_client_connect_handoff' or row['function'] != '_check' or
                type(row['line']) is not int or not 1 <= row['line'] <= 3):
            return False
    return True


def validate(value):
    fields = {'schema', 'passed', 'blocks', 'error', 'modules_restored', 'hooks_restored',
        'all_threads_joined', 'owned_fixture_namespaces_cleared', 'trace_namespace_cleared',
        'python_version', 'ledger_rows', 'calls_per_block', 'groups', 'call_count',
        'thread_cpu_collected', 'trace_source_verified', 'elapsed_seconds'}
    need(type(value) is dict and set(value) == fields and value['schema'] == SCHEMA, 'model_fields')
    bools = ('passed', 'modules_restored', 'hooks_restored', 'all_threads_joined',
        'owned_fixture_namespaces_cleared', 'trace_namespace_cleared', 'thread_cpu_collected',
        'trace_source_verified')
    need(all(type(value[key]) is bool for key in bools) and value['thread_cpu_collected'] is False,
         'model_flags')
    need(type(value['python_version']) is tuple and value['python_version'] == (3, 5, 5) and
         all(type(item) is int for item in value['python_version']), 'model_python')
    for key, expected in (('ledger_rows', LEDGER_ROWS), ('calls_per_block', CALLS_PER_BLOCK),
                          ('groups', GROUPS), ('call_count', CALL_COUNT)):
        need(type(value[key]) is int and value[key] == expected, 'model_constants')
    need(value['error'] is None or (type(value['error']) is str and
         value['error'].isascii() and value['error'].isidentifier() and len(value['error']) <= 64), 'model_error')
    need(finite(value['elapsed_seconds'], ALARM), 'model_elapsed')
    rows = value['blocks']
    need(type(rows) is tuple and 0 <= len(rows) <= GROUPS * len(ORDER), 'model_blocks')
    row_fields = {'group', 'slot', 'mode', 'returned', 'checksum', 'wall_seconds', 'process_cpu_seconds',
        'worker_error', 'worker_hook_expected', 'worker_hook_restored', 'thread_joined',
        'main_hook_restored', 'default_hook_restored', 'original_modules_verified', 'trace_result'}
    flags = ('worker_hook_expected', 'worker_hook_restored', 'thread_joined',
        'main_hook_restored', 'default_hook_restored', 'original_modules_verified')
    trace_fields = {'schema', 'thread_trace_installed', 'thread_trace_hook_restored', 'trace_unknown',
                    'overflow_unknown', 'failure_codes', 'events', 'terminal'}
    expected = CALLS_PER_BLOCK * LEDGER_ROWS * (LEDGER_ROWS - 1) // 2
    for index, row in enumerate(rows):
        need(type(row) is dict and set(row) == row_fields and
             type(row['group']) is int and row['group'] == index // len(ORDER) and
             type(row['slot']) is int and row['slot'] == index % len(ORDER) and
             row['mode'] == ORDER[index % len(ORDER)], 'model_block_order')
        need(all(type(row[key]) is bool for key in flags) and type(row['returned']) is int and
             0 <= row['returned'] <= CALLS_PER_BLOCK and type(row['checksum']) is int and
             row['checksum'] == row['returned'] * LEDGER_ROWS * (LEDGER_ROWS - 1) // 2, 'model_receipt')
        need(row['worker_error'] is None or (type(row['worker_error']) is str and
             row['worker_error'].isascii() and row['worker_error'].isidentifier() and
             len(row['worker_error']) <= 64), 'model_worker_error')
        for key in ('wall_seconds', 'process_cpu_seconds'):
            need(row[key] is None or finite(row[key], ALARM), 'model_timing')
        trace = row['trace_result']
        need(trace is None or (type(trace) is dict and set(trace) == trace_fields and
             trace['schema'] == 'receive-handoff-trace-v1' and
             all(type(trace[key]) is bool for key in ('thread_trace_installed',
                 'thread_trace_hook_restored', 'trace_unknown', 'overflow_unknown')) and
             type(trace['failure_codes']) is tuple and len(trace['failure_codes']) <= 10 and
             all(type(code) is str and code.isascii() and code.isidentifier() and len(code) <= 64
                 for code in trace['failure_codes']) and trace_events(trace['events']) and
             trace['terminal'] is None), 'model_trace')
        if row['mode'] == 'none':
            need(trace is None and row['original_modules_verified'] is False, 'model_none')
        if value['passed']:
            need(row['returned'] == CALLS_PER_BLOCK and row['checksum'] == expected and
                 row['worker_error'] is None and all(row[key] is True for key in flags[:-1]) and
                 all(finite(row[key], BLOCK_CAP) for key in ('wall_seconds', 'process_cpu_seconds')),
                 'model_block_pass')
            if row['mode'] == 'actual_trace':
                need(row['original_modules_verified'] is True and trace is not None and
                     trace['thread_trace_installed'] is True and trace['thread_trace_hook_restored'] is True and
                     trace['trace_unknown'] is False and trace['overflow_unknown'] is False and
                     trace['failure_codes'] == () and trace['events'] == (), 'model_trace_pass')
    if value['passed']:
        need(value['error'] is None and len(rows) == GROUPS * len(ORDER) and
             all(value[key] is True for key in bools[1:6] + ('trace_source_verified',)) and
             finite(value['elapsed_seconds'], MODEL_BUDGET), 'model_pass')
    return value


def summary(rows):
    groups = []
    for group in range(GROUPS):
        part = [row for row in rows if row['group'] == group]
        need(tuple(row['mode'] for row in part) == ORDER, 'summary_order')
        item = dict(group=group, order=list(ORDER))
        for field in ('wall_seconds', 'process_cpu_seconds'):
            a = sum(row[field] for row in part if row['mode'] == 'none') / (2 * CALLS_PER_BLOCK)
            b = sum(row[field] for row in part if row['mode'] == 'actual_trace') / (2 * CALLS_PER_BLOCK)
            item[field] = dict(none_per_call=a, actual_trace_per_call=b,
                delta_per_call=b - a, actual_trace_slower=b > a, ratio=b / a if a > 0 else None)
        groups.append(item)
    return groups


def model_reply(adb, command, target, receipts):
    label = 'trace-overhead-model'
    try:
        raw = adb.run(label, ['shell', command], timeout=HOST_TIMEOUT, input_data=target)
    finally:
        stem = '%02d-%s' % (adb.index, label)
        receipt = dict(host_exit=None, remote_exit=None, stdout_bytes=None, stderr_bytes=None)
        for suffix, field in (('stdout.raw', 'stdout_bytes'), ('stderr.raw', 'stderr_bytes')):
            path = adb.directory / (stem + '.' + suffix)
            if path.exists(): receipt[field] = path.stat().st_size
        path = adb.directory / (stem + '.host-exit')
        if path.exists():
            text = path.read_text(encoding='ascii')
            receipt['host_exit'] = int(text) if re.fullmatch(r'-?[0-9]+', text) else text
        path = adb.directory / (stem + '.stdout.raw')
        if path.exists():
            matches = re.findall(rb'(?m)^MTA_REMOTE_EXIT=([0-9]+)\r*$', path.read_bytes())
            if len(matches) == 1: receipt['remote_exit'] = int(matches[0])
        receipts[label] = receipt
    need(len(raw) <= OUTPUT_LIMIT and receipt['stderr_bytes'] == 0 and
         receipt['host_exit'] == 0, 'model_streams')
    text = raw.decode('ascii').replace('\r\r\n', '\n').replace('\r\n', '\n')
    # ADB's PTY may echo the complete stdin source. Accept only that exact
    # previously supplied source prefix; never discard arbitrary extra output.
    echo = target.decode('ascii')
    if text.startswith(echo):
        text = text[len(echo):]
    lines = text.splitlines()
    lines = [line for line in lines if line]
    need(len(lines) == 2 and lines[0].startswith('TRACE_OVERHEAD_MODEL=') and
         lines[1] in ('MTA_REMOTE_EXIT=0', 'MTA_REMOTE_EXIT=1'), 'model_envelope')
    value = validate(ast.literal_eval(lines[0][len('TRACE_OVERHEAD_MODEL='):]))
    need(receipt['remote_exit'] == (0 if value['passed'] else 1), 'model_remote_exit')
    return value


def run(device):
    raw = (BASE / PINS[0][0]).read_bytes()
    need((len(raw), digest(raw)) == PINS[0][1:], 'sealer_pin')
    seal = definitions(PINS[0][0], raw)
    mode = 'device-model' if device else 'source'
    out = BASE / 'results' / ('receive-trace-overhead-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs = {PINS[0][0]: raw}
    evidence = seal.InputEvidence(inputs)
    report = dict(schema=SCHEMA + '-parent', mode=mode, passed=False, error=None,
        device_attempted=False, model_attempted=False, observation=None, group_comparison=None,
        source_preserved=False, stock_before_ok=False, stock_after_ok=False,
        limited_stock_unchanged=False, wifi_state_unchanged=False, command_receipts={}, input_pins=[],
        trace_bytes=PINS[4][1], trace_sha256=PINS[4][2], ledger_rows=LEDGER_ROWS,
        groups=GROUPS, order=list(ORDER), calls_per_block=CALLS_PER_BLOCK, call_count=CALL_COUNT,
        block_join_cap_seconds=BLOCK_CAP, model_budget_seconds=MODEL_BUDGET,
        target_alarm_seconds=ALARM, target_host_timeout_seconds=HOST_TIMEOUT,
        baseline_alarm_seconds=60, baseline_host_timeout_seconds=70, thread_cpu_collected=False,
        timed_setup_install_close_join=False, selected_check_fixture_only=True,
        actual_handoff_check_executed=False, real_trial_owner_executed=False,
        production_trace_methods_replaced=False, dispatch_counter_used=False,
        old_main_called=False, old_tests_replayed=0, graph_loaded=False, phone_entry_loaded=False,
        device_writes=False, staging_performed=False, rf=False, ui=False,
        p011_startup_performance_verified=False, admission_verified=False, full_restore_verified=False)
    adb = probe = helper = before = baseline = None
    failure = None
    expected_count = len(PINS) + 2
    try:
        for key, size, pin in PINS[1:]:
            evidence.read(BASE / key, key=key, pin=(size, pin))
        for key in (SELF, CMD):
            evidence.read(BASE / key, key=key)
        evidence.snapshot(out, lambda key: key)
        probe = definitions(PINS[1][0], inputs[PINS[1][0]])
        helper = definitions(PINS[2][0], inputs[PINS[2][0]])
        target, derivation = make_target(inputs[PINS[3][0]], inputs[PINS[4][0]])
        seal.fresh(out / 'private-raw/target.py', target)
        report.update(derivation=derivation, target_bytes=len(target), target_sha256=digest(target),
            target_limit=TARGET_LIMIT, target_max_line=TARGET_MAX_LINE, stdout_limit=OUTPUT_LIMIT,
            alarm_before_stdin=True, model_host_exit='NOT_RUN', model_remote_exit='NOT_RUN')
        packed = base64.b64encode(zlib.compress(probe.source().encode('utf-8'))).decode('ascii')
        baseline = ('/usr/bin/python3.5 -I -B -c "import signal,base64,zlib;signal.alarm(60);'
            'exec(zlib.decompress(base64.b64decode(\'' + packed + '\')))"; '
            'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
        command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(30);'
            'exec(sys.stdin.buffer.read(' + str(len(target)) + '))" p011-receive-trace-overhead-v1; '
            'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
        need(len(baseline) <= 3500, 'baseline_command_limit')
        seal.fresh(out / 'private-raw/commands.txt', (baseline + '\n' + command + '\n').encode('ascii'))
        if device:
            adb = probe.Adb(out / 'private-raw')
            report['device_attempted'] = True
            before = helper.stock_probe(adb, probe, 'stock-before', baseline, report['command_receipts'])
            report['stock_before_ok'] = True
            report['model_attempted'] = True
            report['observation'] = model_reply(adb, command, target, report['command_receipts'])
            need(report['observation']['passed'] is True, 'model_failed')
            report['group_comparison'] = summary(report['observation']['blocks'])
    except BaseException as error:
        failure = error
        seal.fresh(out / 'private-raw/host-exception.txt', traceback.format_exc().encode('utf-8'))
    finally:
        if adb is not None:
            try:
                after = helper.stock_probe(adb, probe, 'stock-after', baseline, report['command_receipts'])
                report['stock_after_ok'] = True
                if before is not None:
                    report['limited_stock_unchanged'] = before['stock'] == after['stock']
                    report['wifi_state_unchanged'] = before['capabilities']['wifi_connected'] is after['capabilities']['wifi_connected']
                    need(report['limited_stock_unchanged'] and report['wifi_state_unchanged'], 'baseline_changed')
            except BaseException as error:
                seal.fresh(out / 'private-raw/after-exception.txt', traceback.format_exc().encode('utf-8'))
                if failure is None: failure = error
        receipt = report['command_receipts'].get('trace-overhead-model')
        if receipt is not None:
            report['model_host_exit'] = receipt['host_exit']
            report['model_remote_exit'] = receipt['remote_exit']
        try:
            for key, expected in tuple(inputs.items()):
                need(evidence.read(BASE / key, key=key) == expected, 'source_changed')
                need((out / 'private-inputs' / key).read_bytes() == expected, 'snapshot_changed')
            need(len(inputs) == expected_count and not evidence.partial, 'input_set_incomplete')
            report['source_preserved'] = True
        except BaseException as error:
            seal.fresh(out / 'private-raw/source-exception.txt', traceback.format_exc().encode('utf-8'))
            if failure is None: failure = error
        try:
            # On a pin/read failure preserve every actually read input/attempt.
            status = out / 'private-raw/input-read-status.json'
            if status.exists():
                seal.fresh(out / 'private-raw/input-read-status-final.json',
                    (json.dumps(dict(partial=sorted(evidence.partial), changed_attempts=[
                        dict(path=key, bytes=len(value), sha256=digest(value))
                        for key, value in evidence.changed_attempts]), sort_keys=True) + '\n').encode('ascii'))
                for index, (key, value) in enumerate(evidence.changed_attempts):
                    seal.fresh(out / 'private-input-attempts' / ('final-%04d.raw' % index), value)
            else:
                evidence.snapshot(out, lambda key: key)
            report['input_count'] = len(inputs)
            report['input_pins'] = [dict(path=key, bytes=len(value), sha256=digest(value),
                complete=key not in evidence.partial) for key, value in inputs.items()]
            if adb is not None:
                for label, item in report['command_receipts'].items():
                    seal.fresh(out / 'private-raw' / (label + '.remote-exit'),
                        (str(item['remote_exit']) + '\n').encode('ascii'))
        except BaseException as error:
            seal.fresh(out / 'private-raw/evidence-exception.txt', traceback.format_exc().encode('utf-8'))
            if failure is None: failure = error
        report['passed'] = failure is None
        if failure is not None:
            report['error'] = type(failure).__name__
            if (type(failure) is ValueError and len(failure.args) == 1 and
                    type(failure.args[0]) is str and failure.args[0].isascii() and
                    failure.args[0].isidentifier() and len(failure.args[0]) <= 64):
                report['error'] += ':' + failure.args[0]
    readme = (b'P011 Python3.5.5 frozen actual TraceOwner cost model; default SOURCE never contacts device.\n'
        b'Explicit --check-device: readonly stock before, fresh stdin model process, readonly stock after.\n'
        b'Four ABBA groups, 16 fresh threads, four calls/block, same selected three-line check and 2000-row ledger.\n'
        b'Fixture only: NOT actual Handoff._check, Trial/Owner lifecycle, admission, phone or Startup workload.\n'
        b'Original TraceOwner/dispatch/original_modules/install/close unchanged; no dispatch counter.\n'
        b'Wall perf_counter and process CPU only; thread CPU unavailable/not collected, not fabricated.\n'
        b'Setup/install/close/join excluded from timed loop; process CPU includes other model-process threads.\n'
        b'Block cap3s/model budget25s/alarm30s/HOST45s; baseline alarm60s/HOST70s separately.\n'
        b'Only all-joined and hook-restored paths restore aliases and clear self-created module dictionaries.\n'
        b'Timeout does not claim drained; isolated process alarm remains the hard exit boundary.\n'
        b'No device staging/writes/RF/UI/business graph/old main/tests; limited stock/Wi-Fi check is not full restoration.\n'
        b'No real P011 Startup benefit or native admission conclusion; measurements are model observations only.\n'
        b'Public ZIP: result.json and README.txt only; exact raw streams/exits/source/pins/snapshots remain private.\n')
    sealed = seal.seal_result(out, report, readme)
    print(json.dumps(dict(passed=sealed['report']['passed'], mode=mode, result_dir=str(out),
        error=sealed['report']['error'], result_zip=str(sealed['archive']),
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    raise SystemExit(run(parser.parse_args().check_device))
