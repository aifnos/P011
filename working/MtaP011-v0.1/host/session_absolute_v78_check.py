"""One new HOST deadline-clamp method; no real thread, device or radio.

Fixed source snapshots and safe successful raw only. Thread.start and clock
are explicit models; this does not test worker/finalizer lifecycle or admission.
"""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
PLAN = 'host/session_absolute_v78_source_manifest.json'
TEST = 'tests/test_transfer_session_absolute_v78.py'
CHECKER = 'host/session_absolute_v78_check.py'
CMD = 'HOST_MTA_SESSION_ABSOLUTE_V78_CHECK.cmd'
PLAN_PIN = (705, '8e531b8a1e9a457d306494ed58f72ce0b26cdd245469dd78456c12651b3e63dc')
PYTHON = Path(r'C:\Users\P011_USER\AppData\Local\Programs\Python\Python312\python.exe')
METHOD = 'AbsoluteSession78Test.test_original_absolute_cap'
MARKER = (b'HOST78_SESSION_CAP new_methods=1 old_methods=0 cases=5 '
          b'threads_model=true device=false phone=false\n')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def fixed(path, pin):
    raw = path.read_bytes()
    if type(pin) is not tuple or (len(raw), sha(raw)) != pin:
        raise ValueError('input_identity_changed')
    return raw


def inputs():
    if Path(sys.executable).resolve() != PYTHON.resolve():
        raise ValueError('fixed_python_required')
    raw = fixed(BASE / PLAN, PLAN_PIN)
    plan = json.loads(raw)
    if (set(plan) != {'schema', 'sources'} or plan['schema'] != 'session-absolute-v78-host-source'
            or type(plan['sources']) is not list or len(plan['sources']) != 3):
        raise ValueError('invalid_plan')
    source = {PLAN: raw, CHECKER: Path(__file__).read_bytes(), CMD: (BASE / CMD).read_bytes()}
    target_count = 0
    for row in plan['sources']:
        if set(row) != {'path', 'bytes', 'sha256', 'python35_target'}:
            raise ValueError('invalid_source_row')
        path = row['path']
        if (type(path) is not str or path.startswith('/') or ':' in path or '\\' in path
                or '..' in path.split('/') or path in source or type(row['python35_target']) is not bool):
            raise ValueError('invalid_source_path')
        value = fixed(BASE / path, (row['bytes'], row['sha256']))
        if row['python35_target']:
            ast.parse(value.decode('utf-8'), feature_version=(3, 5))
            target_count += 1
        source[path] = value
    if len(source) != 6 or target_count != 2 or TEST not in source:
        raise ValueError('source_count_changed')
    tree = ast.parse(source[TEST].decode('utf-8'))
    methods = [node.name + '.' + method.name for node in tree.body if isinstance(node, ast.ClassDef)
               for method in node.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')]
    if methods != [METHOD]: raise ValueError('unexpected_test_method')
    return source


def main():
    if len(sys.argv) != 1:
        print('HOST_ONLY no device arguments')
        return 2
    run = BASE / 'results' / ('session-absolute-v78-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    run.mkdir()
    private = run / 'private-inputs'
    source, rows, error, python_pin = {}, [], None, None
    try:
        source = inputs()
        binary = PYTHON.read_bytes()
        python_pin = (len(binary), sha(binary))
        for path, raw in sorted(source.items()):
            target = private / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            if target.read_bytes() != raw: raise ValueError('snapshot_changed')
            rows.append({'path': path, 'bytes': len(raw), 'sha256': sha(raw)})
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, SyntaxError):
        error = 'source_snapshot_invalid'
    started = time.monotonic()
    stdout, stderr, code, invoked, timeout = b'', b'', None, False, False
    if error is None:
        environment = dict(os.environ)
        environment.pop('PYTHONPATH', None)
        environment.pop('PYTHONSTARTUP', None)
        try:
            child = subprocess.run([str(PYTHON), '-I', '-B', str(private / TEST), '-q'],
                cwd=str(private), env=environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
            stdout, stderr, code, invoked = child.stdout, child.stderr, child.returncode, True
        except subprocess.TimeoutExpired as failure:
            stdout, stderr, invoked, timeout = failure.stdout or b'', failure.stderr or b'', True, True
        except OSError:
            error = 'child_not_started'
    elapsed = time.monotonic() - started
    (run / 'stdout.raw').write_bytes(stdout)
    (run / 'stderr.raw').write_bytes(stderr)
    preserved = bool(source)
    try:
        preserved = all((BASE / path).read_bytes() == raw for path, raw in source.items()) and preserved
        binary = PYTHON.read_bytes()
        tools_preserved = python_pin is not None and (len(binary), sha(binary)) == python_pin
    except OSError:
        preserved, tools_preserved = False, False
    marker_ok = stdout in (MARKER, MARKER.replace(b'\n', b'\r\n'))
    summary_ok = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = bool(error is None and invoked and not timeout and code == 0 and preserved
                  and tools_preserved and marker_ok and summary_ok)
    value = dict(schema='session-absolute-v78-host', passed=passed, verification_error=error,
        inputs=rows, source_snapshot_count=len(rows), sources_preserved=preserved,
        runtime_python35_ast=bool(source), runtime_source_count=2 if source else 0,
        method=METHOD, cases=5, new_methods_invoked=int(invoked), old_methods_invoked=0,
        child_invocations=int(invoked), child_exit=code, child_timeout=timeout, elapsed_seconds=elapsed,
        stdout_bytes=len(stdout), stdout_sha256=sha(stdout), stderr_bytes=len(stderr), stderr_sha256=sha(stderr),
        fixed_marker_verified=marker_ok, unittest_summary_verified=summary_ok,
        python_version=sys.version.split()[0], python_pin=python_pin, python_preserved=tools_preserved,
        thread_start_model=True, real_worker_thread_started=False, task_body_executed=False,
        finalizer_body_executed=False, progress_ipc_executed=False, admission_issued=False,
        device_accessed=False, phone_tested=False, rf_requested=False, candidate_deployed=False,
        physical_restore_verified=False, send_available=False, receive_available=False)
    raw_result = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'One new HOST method, five original absolute deadline boundary cases. '
        b'Actual Session78 definitions; clock and Thread.start are declared models. '
        b'No task/finalizer body, real worker, admission, parent/F IPC, ADB, P011, '
        b'phone, RF or physical restoration. No old methods replayed. Failure raw '
        b'stays private; successful raw requires exact safe marker and Ran1/OK.\n')
    (run / 'result.json').write_bytes(raw_result)
    (run / 'README.txt').write_bytes(readme)
    members = {'result.json': raw_result, 'README.txt': readme}
    if passed: members.update({'stdout.raw': stdout, 'stderr.raw': stderr})
    archive = run / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as output:
        for name, raw in members.items(): output.writestr(name, raw)
    with zipfile.ZipFile(archive) as output:
        if output.namelist() != list(members) or output.testzip() is not None or any(
                output.read(name) != raw for name, raw in members.items()):
            raise ValueError('public_zip_changed')
    print(json.dumps(dict(passed=passed, child_exit=code, timeout=timeout,
        elapsed_seconds=elapsed, result_zip=str(archive), zip_sha256=sha(archive.read_bytes()))))
    return 0 if passed else 2 if error else 1


if __name__ == '__main__': sys.exit(main())
