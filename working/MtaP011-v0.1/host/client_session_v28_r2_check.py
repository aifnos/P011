"""Pinned PC-only v28 methods. Never ADB, radio, Linux service or deployment.

Each invocation selects one fixed method and captures its FIRST raw streams.
Private input snapshots preserve failed revisions. ZIP contains fixed public
facts; raw failure diagnostics are local only. A model is not hardware proof.
"""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
PLAN = 'host/client_session_v28_r2_source_manifest.json'
PLAN_SHA = '154f6fd68dfecd3e8efd7080680a61a7703fd97e862f9464c105ae50d2f5c820'
OLD_PLAN = 'host/client_session_v28_source_manifest.json'
OLD_SHA = '60474fa6cd30aab486568fd05046233df24092133cdbb23bb7efc6f926b26060'
CHANGED = {'mta_client_linux_provider', 'mta_client_dynamic_ip'}
TESTS = {
    'lifecycle': ('tests/test_client_session_lifecycle_v28_r2.py',
        'a988cff9c7e659ee95b9c4982a8540ba611a7e270b9a3c2e8ff58ced6474a30e',
        'SessionLifecycleV28R2Tests.test_native_formal300_f_dora_dynamic_ip_durable_restore_and_original_cap',
        240, 'actual 30-definition F/INIT/CONNECT/DORA/IP/Store/restore over synthetic OS/kernel/clock'),
}

def fixed(relative, pin, size=None):
    value = (BASE / relative).read_bytes()
    if hashlib.sha256(value).hexdigest() != pin or size is not None and len(value) != size:
        raise ValueError('fixed_input_changed')
    return value


def verify(stage):
    plan_raw, old_raw = fixed(PLAN, PLAN_SHA), fixed(OLD_PLAN, OLD_SHA)
    plan, old = json.loads(plan_raw), json.loads(old_raw)['sources']
    if set(plan) != {'schema', 'previous_manifest_sha256', 'sources'} or \
            plan['schema'] != 'client-session-v28-r2-host' or plan['previous_manifest_sha256'] != OLD_SHA:
        raise ValueError('plan_invalid')
    rows = plan['sources']
    if len(rows) != 30 or [r['module'] for r in rows] != [r['module'] for r in old]:
        raise ValueError('graph_invalid')
    inputs = {PLAN: plan_raw, OLD_PLAN: old_raw}
    for row, previous in zip(rows, old):
        if row['module'] not in CHANGED and row != previous: raise ValueError('old_source_changed')
    for row in rows:
        if set(row) != {'module', 'path', 'sha256', 'bytes'}: raise ValueError('row_invalid')
        if row['module'] in CHANGED or row['module'] == 'mta_client_dynamic_ip':
            if row['path'] != 'candidate/client-session-v28-r2/runtime/' + row['module'] + '.py':
                raise ValueError('new_source_path_invalid')
        raw = fixed(row['path'], row['sha256'], row['bytes'])
        inputs[row['path']] = raw
        tree = ast.parse(raw.decode('utf-8'), filename=row['path'], feature_version=(3, 5))
        if any(isinstance(n, ast.Assert) for n in ast.walk(tree)): raise ValueError('target_assert')
        if row['module'] == 'mta_client_executor':
            values = [n.value for n in tree.body if isinstance(n, ast.Assign) and
                any(isinstance(t, ast.Name) and t.id == 'MODULES' for t in n.targets)]
            if len(values) != 1 or ast.literal_eval(values[0]) != tuple(r['module'] for r in rows):
                raise ValueError('executor_graph_invalid')
    test, pin, method, cap, model = TESTS[stage]
    test_raw = fixed(test, pin)
    inputs[test] = test_raw
    tree = ast.parse(test_raw.decode('utf-8'), filename=test)
    methods = [c.name + '.' + m.name for c in tree.body if isinstance(c, ast.ClassDef)
        for m in c.body if isinstance(m, ast.FunctionDef) and m.name.startswith('test_')]
    if methods != [method]: raise ValueError('method_scope_invalid')
    return rows, inputs, (test, pin, method, cap, model)


def standard_output(stdout, stderr, stage, rows):
    allowed = (b'',)
    if stage == 'schema':
        names = ('p011_json', 'mta_ip', 'mta_p2p_client_init',
            'mta_client_journal_codec', 'mta_client_dynamic_ip')
        facts = [(name, next(r['sha256'] for r in rows if r['module'] == name),
            next(r['bytes'] for r in rows if r['module'] == name)) for name in names]
        marker = ('HOST_SESSION_SCHEMA_V28_ONLY ' + repr(facts)).encode('ascii')
        allowed = (marker + b'\n', marker + b'\r\n')
    return stdout in allowed and re.fullmatch(
        rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in TESTS:
        print('PC_ONLY: choose only fixed lifecycle stage; no device/path arguments')
        return 2
    stage = sys.argv[1]
    try:
        rows, inputs, selected = verify(stage)
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, UnicodeError):
        print('PC_ONLY_FAIL: fixed source or method invalid; no target executed')
        return 2
    test, pin, method, cap, model = selected
    output = BASE / 'results' / ('client-session-v28-r2-' + stage + '-'
        + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    checker_raw = Path(__file__).read_bytes()
    inputs['host/client_session_v28_check.py'] = checker_raw
    for relative, raw in inputs.items():
        target = output / 'private-inputs' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    before, timeout = time.monotonic(), False
    try:
        child = subprocess.run([sys.executable, '-B', str(BASE / test), '-q', method],
            cwd=str(BASE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=cap, check=False)
        stdout, stderr, code = child.stdout, child.stderr, child.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code, timeout = error.stdout or b'', error.stderr or b'', None, True
    duration = time.monotonic() - before
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    passed = not timeout and code == 0 and standard_output(stdout, stderr, stage, rows)
    value = dict(schema='client-session-v28-r2-host', stage=stage, source_manifest_sha256=PLAN_SHA,
        checker_sha256=hashlib.sha256(checker_raw).hexdigest(),
        source_count=30, sources=rows, source_integrity_verified=True,
        python35_syntax_verified=True, old_sources_preserved=True,
        selected_method=method, test_sha256=pin, selected_method_count=1,
        host_exit=code, host_elapsed_seconds=duration, timeout=timeout,
        host_method_passed=passed, model=model,
        host_target_method_completed=passed, full_client_ip_lifecycle_completed=passed and stage == 'lifecycle',
        device_accessed=False, rf_requested=False, device_restoration_verified=False,
        actual_linux_ip_installed=False, actual_endpoint_verified=False,
        send_available=False, receive_available=False, phone_tested=False,
        full_syscall_wall_bound_verified=False, full_heap_bound_verified=False,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(), public_raw_included=passed)
    encoded = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
    note = ('PC HOST ' + stage + ' model only. No ADB, RF, deployment, real IP installation, '
        'endpoint, file transfer or phone acceptance. Failed raw streams and source snapshots stay local.\n').encode('ascii')
    (output / 'result.json').write_bytes(encoded)
    (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(str(archive), 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', encoded); bundle.writestr('README.txt', note)
        if passed:
            bundle.writestr('stdout.raw', stdout); bundle.writestr('stderr.raw', stderr)
    with zipfile.ZipFile(str(archive)) as bundle:
        expected = ['result.json', 'README.txt'] + (['stdout.raw', 'stderr.raw'] if passed else [])
        if bundle.namelist() != expected or bundle.testzip() is not None or \
                bundle.read('result.json') != encoded or bundle.read('README.txt') != note:
            raise ValueError('archive_invalid')
    print(json.dumps(dict(stage=stage, passed=passed, host_exit=code, timeout=timeout,
        elapsed_seconds=duration, result_zip=str(archive),
        zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()), ensure_ascii=False))
    return 0 if passed else 1


if __name__ == '__main__': sys.exit(main())
