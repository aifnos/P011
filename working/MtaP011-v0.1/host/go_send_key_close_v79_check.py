"""One new HOST key-close method; fake FFI only, no real native key.

Actual frozen crypto and Bridge79 definitions; stable fake EC library functions
and explicit State/deployment/clock antecedents. No process, pipe, RF or device.
Successful raw requires fixed safe marker; failed raw stays private.
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
PLAN = 'host/go_send_key_close_v79_source_manifest.json'
TEST = 'tests/test_go_send_key_close_v79.py'
CHECKER = 'host/go_send_key_close_v79_check.py'
CMD = 'HOST_MTA_GO_SEND_KEY_CLOSE_V79_CHECK.cmd'
PLAN_PIN = (1283, 'f8a75beba481090adf72c178975e53723d9ce3695c765a9761df965a181b9026')
PYTHON = Path(r'C:\Users\P011_USER\AppData\Local\Programs\Python\Python312\python.exe')
METHOD = 'GoSendKeyClose79Test.test_original_key_inventory_and_close'
MARKER = (b'HOST79_GO_SEND_KEY_CLOSE new_methods=1 old_methods=0 '
          b'key_free_model=true device=false phone=false\n')


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
    if (set(plan) != {'schema', 'sources'} or plan['schema'] != 'go-send-key-close-v79-host-source'
            or type(plan['sources']) is not list or len(plan['sources']) != 6):
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
    if len(source) != 9 or target_count != 4 or TEST not in source:
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
    run = BASE / 'results' / ('go-send-key-close-v79-host-' +
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
    value = dict(schema='go-send-key-close-v79-host', passed=passed, verification_error=error,
        inputs=rows, source_snapshot_count=len(rows), sources_preserved=preserved,
        runtime_python35_ast=bool(source), runtime_source_count=4 if source else 0,
        method=METHOD, cases=15, new_methods_invoked=int(invoked), old_methods_invoked=0,
        child_invocations=int(invoked), child_exit=code, child_timeout=timeout, elapsed_seconds=elapsed,
        stdout_bytes=len(stdout), stdout_sha256=sha(stdout), stderr_bytes=len(stderr), stderr_sha256=sha(stderr),
        fixed_marker_verified=marker_ok, unittest_summary_verified=summary_ok,
        python_version=sys.version.split()[0], python_pin=python_pin, python_preserved=tools_preserved,
        key_free_model=True, real_libcrypto_release_verified=False, crypto_math_verified=False,
        actual_crypto_definitions=True, actual_bridge_key_close_definitions=True,
        state_admission_model=True, clock_model=True, real_worker_thread_started=False,
        task_body_executed=False, finalizer_body_executed=False, progress_ipc_executed=False,
        parent_f_ipc_executed=False, admission_issued=False,
        device_accessed=False, phone_tested=False, rf_requested=False, candidate_deployed=False,
        physical_restore_verified=False, send_available=False, receive_available=False)
    raw_result = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'One new HOST method, fifteen independent key inventory fixtures. '
        b'Actual crypto generation/KeyPair.close and Bridge79 key bookkeeping. '
        b'Stable fake EC functions and pointers are models, NOT libcrypto allocation, '
        b'mathematics or real release. State/deployment/clock are declared models. '
        b'No process/pipe/GO/GATT/ADB/P011/phone/admission/restoration executed. '
        b'No old methods replayed. Failure raw stays private; successful raw '
        b'requires exact safe marker and Ran1/OK.\n')
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

