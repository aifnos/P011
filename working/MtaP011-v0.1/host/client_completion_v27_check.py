"""PC-only one-method completion boundary check, never device/RF execution."""
import ast
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
KIND = 'client-completion-v27-host-boundary'
PLAN = 'host/client_completion_v27_source_manifest.json'
PLAN_SHA = 'd1a3435c3f021a10c618d2967e2682791832f9f024902df71a05ce058e1b1213'
PREVIOUS = 'host/client_formal_v26_source_manifest.json'
PREVIOUS_SHA = '1dbfc59425315d8ab2bcc3bf4a60aaa551fdb36d8707d884d5f9a512a694d586'
PREVIOUS_CHECK = 'host/client_formal_v26_source_check.py'
PREVIOUS_CHECK_SHA = '86f5e074a97fd7523272cff4fadc48b8c67508214ff9b24a43fbac45c3556821'
TEST = 'tests/test_client_formal_completion_deadline_v27.py'
TEST_SHA = 'b040b4f7a6b109a65203df1289284fe9572fef5f323d568bf63af808252c9965'


def fixed(relative, pin, count=None):
    raw = (BASE / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin or count is not None and len(raw) != count:
        raise ValueError('fixed_source_changed')
    return raw


def verify():
    # Import only the pinned PC checker. Its main/package generator is not run.
    fixed(PREVIOUS_CHECK, PREVIOUS_CHECK_SHA)
    spec = importlib.util.spec_from_file_location('PC_v26_static', str(BASE / PREVIOUS_CHECK))
    previous_check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(previous_check)
    previous, unused = previous_check.verify()
    fixed(PREVIOUS, PREVIOUS_SHA)
    plan = json.loads(fixed(PLAN, PLAN_SHA))
    if set(plan) != {'schema', 'previous_manifest_sha256', 'sources'} or \
            plan['schema'] != 'client-completion-v27-source-only' or \
            plan['previous_manifest_sha256'] != PREVIOUS_SHA:
        raise ValueError('plan_invalid')
    rows = plan['sources']
    if type(rows) is not list or len(rows) != 29 or \
            [r['module'] for r in rows] != [r['module'] for r in previous]:
        raise ValueError('graph_order_changed')
    for row, old in zip(rows, previous):
        if row['module'] == 'mta_client_executor':
            expected = dict(module='mta_client_executor',
                path='candidate/client-completion-v27/runtime/mta_client_executor.py',
                sha256='0c6bb9c96e9d79e828f2a9482926868865914e14a3432419ebf48813cde7fdca',
                bytes=75843)
            if row != expected: raise ValueError('executor_changed')
        elif row != old: raise ValueError('frozen_source_changed')
        tree = ast.parse(fixed(row['path'], row['sha256'], row['bytes']).decode('utf-8'),
            filename=row['path'], feature_version=(3, 5))
        if row['module'] == 'mta_client_executor':
            values = [n.value for n in tree.body if isinstance(n, ast.Assign) and
                any(isinstance(t, ast.Name) and t.id == 'MODULES' for t in n.targets)]
            if len(values) != 1 or ast.literal_eval(values[0]) != tuple(r['module'] for r in rows):
                raise ValueError('executor_graph_changed')
    test_tree = ast.parse(fixed(TEST, TEST_SHA).decode('utf-8'), filename=TEST)
    methods = [c.name + '.' + m.name for c in test_tree.body if isinstance(c, ast.ClassDef)
        for m in c.body if isinstance(m, ast.FunctionDef) and m.name.startswith('test_')]
    if len(methods) != 1: raise ValueError('test_method_scope_changed')
    return rows, methods[0]


def standard_output(stdout, stderr):
    return stdout == b'' and re.fullmatch(
        rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY: no device, path, network or test selection arguments accepted')
        return 2
    try:
        rows, method = verify()
    except (OSError, ValueError, SyntaxError, UnicodeError, TypeError, KeyError):
        print('PC_ONLY_FAIL: source pins/syntax/method scope mismatch; no device action')
        return 2
    output = BASE / 'results' / (KIND + '-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
        + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    before = time.monotonic()
    timed_out = False
    try:
        child = subprocess.run([sys.executable, '-B', str(BASE / TEST), '-q', method],
            cwd=str(BASE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=False)
        stdout, stderr, code = child.stdout, child.stderr, child.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code = error.stdout or b'', error.stderr or b'', None
        timed_out = True
    duration = time.monotonic() - before
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    # Public raw streams only for the exact ordinary one-test success shape.
    # Failure diagnostics remain immutable local originals, never auto-shared.
    standard = standard_output(stdout, stderr)
    passed = not timed_out and code == 0 and standard
    public = dict(schema=KIND, source_count=29, sources=rows,
        source_integrity_verified=True, previous_sources_preserved=True,
        python35_syntax_verified=True, test_sha256=TEST_SHA, selected_method=method,
        host_exit=code, timeout=timed_out, host_elapsed_seconds=duration,
        host_boundary_method_passed=passed, host_target_definitions_executed=True,
        tests_run=1, full_formal_lifecycle_executed=False,
        model='unit collaborators; native completion and native Proc history only',
        all_syscall_wall_bound_verified=False, heap_bound_verified=False,
        device_accessed=False, rf_requested=False, device_restoration_verified=False,
        formal_profile_enabled=False, ip_installed=False, endpoint_verified=False,
        send_available=False, receive_available=False, phone_tested=False,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(), public_raw_included=passed)
    encoded = (json.dumps(public, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
    note = b'PC unit boundary only. Not a lifecycle, installer, device, radio, IP, endpoint, transfer or phone acceptance. Raw failures stay local. Success decision sampling is bounded; writes/flushes are not.\n'
    (output / 'result.json').write_bytes(encoded)
    (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(str(archive), 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', encoded)
        bundle.writestr('README.txt', note)
        if passed:
            bundle.writestr('stdout.raw', stdout)
            bundle.writestr('stderr.raw', stderr)
    with zipfile.ZipFile(str(archive)) as bundle:
        expected = ['result.json', 'README.txt'] + (['stdout.raw', 'stderr.raw'] if passed else [])
        if bundle.namelist() != expected or bundle.testzip() is not None or \
                bundle.read('result.json') != encoded or bundle.read('README.txt') != note:
            raise ValueError('archive_invalid')
    print(json.dumps(dict(host_boundary_pass=passed, host_exit=code,
        elapsed_seconds=duration, result_zip=str(archive),
        zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()), ensure_ascii=False))
    return 0 if passed else 1


if __name__ == '__main__': sys.exit(main())
