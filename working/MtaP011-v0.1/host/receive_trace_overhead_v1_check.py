"""Bounded HOST-only cost observation of the frozen actual TraceOwner.

The ordinary namespace/thread/2000-row ledger fixture is NOT a real Trial,
Owner, admission, P011 workload or device-performance result. No old entry,
test, graph or phone source is loaded. Production tracing methods are unchanged.
"""
import argparse
import datetime
import hashlib
import json
import math
from pathlib import Path
import platform
import secrets
import subprocess
import sys
import threading
import time
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/receive_trace_overhead_v1_check.py'
CMD = 'HOST_MTA_RECEIVE_TRACE_OVERHEAD_V1_CHECK.cmd'
TRACE = ('candidate/receive-handoff-trace-v1/runtime/handoff_trace.py', 14820,
         '990cbf387893706e263abc43aa4fdc728782c4a0a88de531d5a1a53274862657')
SCHEMA = 'p011-receive-trace-overhead-v1-host'
LEDGER_ROWS = 2000
CALLS_PER_BLOCK = 4
GROUPS = 4
ORDER = ('none', 'actual_trace', 'actual_trace', 'none')
CALL_COUNT = GROUPS * len(ORDER) * CALLS_PER_BLOCK
BLOCK_JOIN_CAP = 2.0
WORKER_BUDGET = 35.0
WORKER_HOST_CAP = 45.0
HOST_CAP = 60.0
OUTPUT_LIMIT = 65536
TRIAL_ROLE = 'mta_receive_trial'
KNOWN_ERRORS = ('trace_pin', 'existing_hook', 'fixture_identity', 'fixture_ledger',
    'block_deadline', 'worker_deadline', 'worker_error', 'block_return', 'hook_restore',
    'trace_projection', 'module_restore', 'output_limit', 'worker_fields', 'worker_exit',
    'source_changed', 'host_deadline', 'missing_thread_cpu')
TRIAL_FIXTURE = '''def inventory(ledger):
    rows, originals, tokens = ledger['rows'], ledger['originals'], ledger['tokens']
    if len(rows) != 2000 or len(originals) != 2000 or len(tokens) != 2000:
        raise ValueError('fixture_ledger')
    if any(type(row) is not dict or row is not originals[index] or
           row['index'] != index or row['closed'] is not True or
           row['token'] is not tokens[index] for index, row in enumerate(rows)):
        raise ValueError('fixture_ledger')
    return sum(row['index'] for row in rows)
'''
SELECTED_FIXTURE = '''def _check(ledger):
    value = trial_inventory(ledger)
    return value
'''


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed_trace():
    raw = (BASE / TRACE[0]).read_bytes()
    need(len(raw) == TRACE[1] and digest(raw) == TRACE[2], 'trace_pin')
    module = types.ModuleType('fixed_host_trace_overhead_v1')
    module.__file__ = '<frozen-host-trace-overhead-v1>'
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def error_code(error):
    if type(error) is ValueError and len(error.args) == 1 and error.args[0] in KNOWN_ERRORS:
        return error.args[0]
    return type(error).__name__


def fixture(trace):
    modules = {role: types.ModuleType(role) for role in trace.ROLE_NAMES}
    trial = types.ModuleType(TRIAL_ROLE)
    exec(compile(TRIAL_FIXTURE, '<host-only-trial-inventory-fixture>', 'exec'), trial.__dict__)
    handoff = modules['mta_client_connect_handoff']
    handoff.trial_inventory = trial.inventory
    exec(compile(SELECTED_FIXTURE, '<host-only-selected-check-fixture>', 'exec'), handoff.__dict__)
    handoff.ReceiveConnectHandoff = type('HostSelectedCheck', (),
        {'_check': staticmethod(handoff._check)})
    loader = types.SimpleNamespace(modules=modules)
    owner = types.SimpleNamespace(loader=loader, service=modules['mta_service'])
    phone = types.ModuleType('host_only_phone_context_fixture')
    phone._RETAINED = types.SimpleNamespace(owner=owner, loader=loader)
    tokens = tuple(object() for unused in range(LEDGER_ROWS))
    rows = tuple(dict(index=index, closed=True, token=tokens[index])
                 for index in range(LEDGER_ROWS))
    ledger = dict(rows=rows, originals=tuple(rows), tokens=tokens)
    check = handoff.ReceiveConnectHandoff._check
    need(type(check) is types.FunctionType and check is handoff._check and
         check.__globals__ is handoff.__dict__ and
         trial.inventory.__globals__ is trial.__dict__ and
         not any(role == TRIAL_ROLE for role, cls, name in trace.SELECTED), 'fixture_identity')
    return phone, modules, trial, ledger, check


def after_restore():
    # This ordinary call lets the UNCHANGED dispatch revoke its own worker hook
    # after the main thread has called the UNCHANGED close_trace. No settrace here.
    return sys.gettrace() is None


def block(trace, phone, ledger, check, group, slot, mode, global_until):
    need(sys.gettrace() is None and getattr(threading, '_trace_hook', object()) is None,
         'existing_hook')
    owner = trace.TraceOwner(phone) if mode == 'actual_trace' else None
    done, release = threading.Event(), threading.Event()
    row = dict(group=group, slot=slot, mode=mode, returned=0, checksum=0,
        wall_seconds=None, process_cpu_seconds=None, thread_cpu_seconds=None,
        worker_error=None, worker_hook_expected=False, worker_hook_restored=False,
        thread_joined=False, main_hook_restored=False, default_hook_restored=False,
        original_modules_verified=False, trace_result=None)
    expected = LEDGER_ROWS * (LEDGER_ROWS - 1) // 2
    until = min(global_until, time.monotonic() + BLOCK_JOIN_CAP)

    def run():
        row['worker_hook_expected'] = (sys.gettrace() is (owner.hook if owner else None))
        wall, cpu, thread_cpu = time.perf_counter(), time.process_time(), time.thread_time()
        try:
            for unused in range(CALLS_PER_BLOCK):
                value = check(ledger)
                need(type(value) is int and value == expected, 'block_return')
                row['checksum'] += value
                row['returned'] += 1
        except BaseException as error:
            row['worker_error'] = error_code(error)
        finally:
            row['thread_cpu_seconds'] = time.thread_time() - thread_cpu
            row['process_cpu_seconds'] = time.process_time() - cpu
            row['wall_seconds'] = time.perf_counter() - wall
            done.set()
            release.wait(BLOCK_JOIN_CAP)
            row['worker_hook_restored'] = after_restore()

    thread = threading.Thread(target=run, name='host-trace-overhead-block', daemon=True)
    try:
        if owner is not None:
            need(owner.dispatch.__func__ is trace.TraceOwner.dispatch and
                 owner.original_modules() is owner.modules and
                 set(owner.modules) == set(trace.ROLE_NAMES), 'fixture_identity')
            row['original_modules_verified'] = True
            owner.install()
        thread.start()
        need(done.wait(max(0.0, until - time.monotonic())), 'block_deadline')
    finally:
        if owner is not None:
            owner.close_trace()
        release.set()
        if thread.ident is not None:
            thread.join(max(0.0, until - time.monotonic()))
        row['thread_joined'] = not thread.is_alive()
        row['main_hook_restored'] = sys.gettrace() is None
        row['default_hook_restored'] = getattr(threading, '_trace_hook', object()) is None
        if owner is not None:
            row['trace_result'] = owner.public()
    need(row['thread_joined'], 'block_deadline')
    need(row['worker_error'] is None, 'worker_error')
    need(row['returned'] == CALLS_PER_BLOCK and row['checksum'] == CALLS_PER_BLOCK * expected,
         'block_return')
    need(row['worker_hook_expected'] and row['worker_hook_restored'] and
         row['main_hook_restored'] and row['default_hook_restored'], 'hook_restore')
    if owner is not None:
        value = row['trace_result']
        need(value['thread_trace_installed'] is True and value['thread_trace_hook_restored'] is True and
             value['trace_unknown'] is False and value['overflow_unknown'] is False and
             value['failure_codes'] == () and value['events'] == () and value['terminal'] is None,
             'trace_projection')
    return row


def summary(blocks):
    fields = ('wall_seconds', 'process_cpu_seconds', 'thread_cpu_seconds')
    groups = []
    for group in range(GROUPS):
        rows = [row for row in blocks if row['group'] == group]
        need(tuple(row['mode'] for row in rows) == ORDER, 'worker_fields')
        item = dict(group=group, order=list(ORDER))
        for field in fields:
            a = sum(row[field] for row in rows if row['mode'] == 'none') / (2 * CALLS_PER_BLOCK)
            b = sum(row[field] for row in rows if row['mode'] == 'actual_trace') / (2 * CALLS_PER_BLOCK)
            item[field] = dict(none_per_call=a, actual_trace_per_call=b,
                delta_per_call=b - a, actual_trace_slower=b > a, ratio=b / a if a > 0 else None)
        groups.append(item)
    return groups


def worker():
    started = time.monotonic()
    report = dict(schema=SCHEMA + '-worker', passed=False, blocks=[], group_comparison=None,
        error=None, modules_restored=False, hooks_restored=False, all_threads_joined=False,
        python_version=platform.python_version(), implementation=platform.python_implementation(),
        ledger_rows=LEDGER_ROWS, calls_per_block=CALLS_PER_BLOCK, groups=GROUPS, call_count=CALL_COUNT)
    previous, missing, registered = {}, object(), {}
    try:
        need(callable(getattr(time, 'thread_time', None)), 'missing_thread_cpu')
        need(sys.gettrace() is None and getattr(threading, '_trace_hook', object()) is None,
             'existing_hook')
        trace = fixed_trace()
        phone, modules, trial, ledger, check = fixture(trace)
        registered = dict(modules); registered[TRIAL_ROLE] = trial
        for role, module in registered.items():
            previous[role] = sys.modules.get(role, missing)
            sys.modules[role] = module
        until = started + WORKER_BUDGET
        for group in range(GROUPS):
            for slot, mode in enumerate(ORDER):
                need(time.monotonic() < until, 'worker_deadline')
                report['blocks'].append(block(trace, phone, ledger, check, group, slot, mode, until))
        report['group_comparison'] = summary(report['blocks'])
    except BaseException as error:
        report['error'] = error_code(error)
    finally:
        unchanged = all(sys.modules.get(role) is module for role, module in registered.items())
        for role in registered:
            if sys.modules.get(role) is registered[role]:
                if previous[role] is missing:
                    del sys.modules[role]
                else:
                    sys.modules[role] = previous[role]
        report['modules_restored'] = unchanged and all(
            sys.modules.get(role, missing) is previous[role] for role in registered)
        report['hooks_restored'] = (sys.gettrace() is None and
            getattr(threading, '_trace_hook', object()) is None)
        report['all_threads_joined'] = not any(
            thread.name == 'host-trace-overhead-block' for thread in threading.enumerate())
        report['elapsed_seconds'] = time.monotonic() - started
    report['passed'] = (report['error'] is None and len(report['blocks']) == GROUPS * len(ORDER) and
        report['modules_restored'] and report['hooks_restored'] and report['all_threads_joined'] and
        report['elapsed_seconds'] <= WORKER_BUDGET)
    print(json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False), flush=True)
    return 0 if report['passed'] else 1


def parse_worker(raw):
    need(len(raw) <= OUTPUT_LIMIT, 'output_limit')
    text = raw.decode('ascii')
    need(len(text.splitlines()) == 1, 'worker_fields')
    value = json.loads(text)
    keys = {'schema', 'passed', 'blocks', 'group_comparison', 'error', 'modules_restored',
        'hooks_restored', 'all_threads_joined', 'python_version', 'implementation', 'ledger_rows',
        'calls_per_block', 'groups', 'call_count', 'elapsed_seconds'}
    need(type(value) is dict and set(value) == keys and value['schema'] == SCHEMA + '-worker',
         'worker_fields')
    need(value['passed'] is True and value['error'] is None and value['ledger_rows'] == LEDGER_ROWS and
         value['calls_per_block'] == CALLS_PER_BLOCK and value['groups'] == GROUPS and
         value['call_count'] == CALL_COUNT and value['modules_restored'] is True and
         value['hooks_restored'] is True and value['all_threads_joined'] is True, 'worker_fields')
    need(type(value['blocks']) is list and len(value['blocks']) == GROUPS * len(ORDER), 'worker_fields')
    expected = CALLS_PER_BLOCK * LEDGER_ROWS * (LEDGER_ROWS - 1) // 2
    for index, row in enumerate(value['blocks']):
        need(type(row) is dict and row['group'] == index // len(ORDER) and
             row['slot'] == index % len(ORDER) and row['mode'] == ORDER[index % len(ORDER)] and
             row['returned'] == CALLS_PER_BLOCK and row['checksum'] == expected and
             row['worker_error'] is None and all(row[key] is True for key in (
                 'worker_hook_expected', 'worker_hook_restored', 'thread_joined',
                 'main_hook_restored', 'default_hook_restored')), 'worker_fields')
        for field in ('wall_seconds', 'process_cpu_seconds', 'thread_cpu_seconds'):
            need(type(row[field]) is float and math.isfinite(row[field]) and
                 0 <= row[field] <= BLOCK_JOIN_CAP, 'worker_fields')
        trace = row['trace_result']
        if row['mode'] == 'actual_trace':
            need(row['original_modules_verified'] is True and type(trace) is dict and
                 trace['schema'] == 'receive-handoff-trace-v1' and
                 trace['thread_trace_installed'] is True and trace['thread_trace_hook_restored'] is True and
                 trace['trace_unknown'] is False and trace['overflow_unknown'] is False and
                 trace['events'] == [] and trace['failure_codes'] == [] and trace['terminal'] is None,
                 'worker_fields')
        else:
            need(trace is None and row['original_modules_verified'] is False, 'worker_fields')
    need(value['group_comparison'] == summary(value['blocks']), 'worker_fields')
    return value


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'source_changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        return worker()
    started = time.monotonic()
    out = BASE / 'results' / ('receive-trace-overhead-v1-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, raw, err = {}, b'', b''
    report = dict(schema=SCHEMA, scope='host-only-explicit-namespace-thread-ledger-fixture',
        passed=False, error=None, host_exit='NOT_RUN', source_preserved=False,
        trace_bytes=TRACE[1], trace_sha256=TRACE[2], ledger_rows=LEDGER_ROWS,
        groups=GROUPS, order=list(ORDER), calls_per_block=CALLS_PER_BLOCK, call_count=CALL_COUNT,
        block_join_cap_seconds=BLOCK_JOIN_CAP, worker_budget_seconds=WORKER_BUDGET,
        worker_host_timeout_seconds=WORKER_HOST_CAP, wrapper_budget_seconds=HOST_CAP,
        stdout_limit=OUTPUT_LIMIT, worker=None, input_pins=[], python_version=platform.python_version(),
        device_python_version='3.5.5', python_versions_differ=True,
        production_trace_methods_replaced=False, real_trial_owner_executed=False,
        dispatch_counter_used=False, old_main_called=False, old_tests_replayed=0,
        graph_loaded=False, phone_entry_loaded=False, device_invoked=False, rf_requested=False,
        admission_verified=False, p011_performance_verified=False, file_transfer_verified=False)
    try:
        for path in (SELF, CMD, TRACE[0]):
            value = (BASE / path).read_bytes()
            inputs[path] = value
            write_new(out / 'private-inputs' / path, value)
            report['input_pins'].append(dict(path=path, bytes=len(value), sha256=digest(value), complete=True))
        need(len(inputs[TRACE[0]]) == TRACE[1] and digest(inputs[TRACE[0]]) == TRACE[2], 'trace_pin')
        command = [sys.executable, '-I', '-B', str(BASE / SELF), '--worker']
        try:
            child = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=WORKER_HOST_CAP, check=False)
            raw, err = child.stdout, child.stderr
            report['host_exit'] = child.returncode
        except subprocess.TimeoutExpired as error:
            raw, err = error.stdout or b'', error.stderr or b''
            report['host_exit'] = 'TIMEOUT'
            raise ValueError('worker_deadline') from None
        need(len(raw) <= OUTPUT_LIMIT and len(err) <= OUTPUT_LIMIT, 'output_limit')
        need(report['host_exit'] == 0 and err == b'', 'worker_exit')
        report['worker'] = parse_worker(raw)
    except BaseException as error:
        report['error'] = error_code(error)
    finally:
        write_new(private / '01-host-worker.stdout.raw', raw)
        write_new(private / '01-host-worker.stderr.raw', err)
        write_new(private / '01-host-worker.host-exit', (str(report['host_exit']) + '\n').encode('ascii'))
        report.update(stdout_bytes=len(raw), stdout_sha256=digest(raw),
            stderr_bytes=len(err), stderr_sha256=digest(err))
        try:
            report['source_preserved'] = len(inputs) == 3 and all(
                (BASE / path).read_bytes() == value and
                (out / 'private-inputs' / path).read_bytes() == value for path, value in inputs.items())
        except BaseException:
            report['source_preserved'] = False
    report['elapsed_seconds'] = time.monotonic() - started
    report['passed'] = (report['error'] is None and report['host_exit'] == 0 and not err and
        report['worker'] is not None and report['worker']['passed'] is True and
        report['source_preserved'] and report['elapsed_seconds'] <= HOST_CAP)
    report['wrapper_exit_derived'] = 0 if report['passed'] else 1
    public = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')
    readme = (b'HOST-only cost observation of frozen actual TraceOwner/dispatch/original_modules.\n'
        b'Ordinary selected _check plus nonselected Trial-style dictionary/generator inventory, 2000 rows.\n'
        b'Four ABBA groups, 16 fresh threads, four calls/block, 64 timed fixture calls; no warmup/counter.\n'
        b'Wall/process CPU/thread CPU are separately observed; process CPU includes other HOST threads.\n'
        b'Actual tracing methods unchanged. Original close_trace and dispatch restore hooks; threads join.\n'
        b'Expected return/checksum equivalent, no workload exception, trace events/failures empty and unknown false.\n'
        b'HOST Python3.12 vs P011 Python3.5.5; no P011 speedup, real Trial/Owner, admission or RF conclusion.\n'
        b'No old entry/test/graph/phone loaded; only three inputs, snapshots and original worker raw/exits private.\n'
        b'Public ZIP contains result.json and README.txt only. Wrapper exit is derived; HOST child exit is raw.\n')
    write_new(out / 'result.json', public); write_new(out / 'README.txt', readme)
    zip_path = out / 'public-result.zip'
    with zipfile.ZipFile(zip_path, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public); bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(zip_path) as bundle:
        need(bundle.namelist() == ['result.json', 'README.txt'] and bundle.testzip() is None and
             bundle.read('result.json') == public and bundle.read('README.txt') == readme, 'source_changed')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        public_result_zip=str(zip_path), zip_sha256=digest(zip_path.read_bytes())), sort_keys=True))
    return report['wrapper_exit_derived']


if __name__ == '__main__':
    raise SystemExit(main())
