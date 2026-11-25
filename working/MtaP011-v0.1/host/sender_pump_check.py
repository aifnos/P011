"""PC-only real loopback TLS sender test; no ADB or radio operations.

Run new tests from immutable input snapshots. Only exact safe successful raw
output is exported. A HOST phone fixture is not Xiaomi/native interoperability.
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
PLAN = 'host/sender_pump_source_manifest.json'
TEST = 'tests/test_sender_pump.py'
CHECKER = 'host/sender_pump_check.py'
CMD = 'HOST_MTA_SENDER_PUMP_CHECK.cmd'
PLAN_PIN = (1588, '91a5265b71d0bbdbda000fed9a771d3674056b20b1a66e0438ba78950bb86cd0')
METHOD = 'SenderPumpTest.test_tls_download_and_terminal_boundaries'
MARKER = (b'HOST_SENDER_PUMP new_methods=1 old_methods=0 loopback_tls=true '
          b'device=false phone=false\n')
OPENSSL = Path(r'C:\Program Files\Git\mingw64\bin\openssl.exe')
OPENSSL_PIN = (1001116, '9c677536ea80e3111fba62784024360e9ea2f1f20391452a6195454ea1fa3faa')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(path, pin):
    raw = path.read_bytes()
    if type(pin) is not tuple or (len(raw), sha(raw)) != pin:
        raise ValueError('input_identity_changed')
    return raw


def inputs():
    plan_raw = fixed(BASE / PLAN, PLAN_PIN)
    plan = json.loads(plan_raw)
    if set(plan) != {'schema', 'sources'} or plan['schema'] != 'sender-pump-host-source':
        raise ValueError('source_manifest_invalid')
    values = {PLAN: plan_raw, CHECKER: Path(__file__).read_bytes(), CMD: (BASE / CMD).read_bytes()}
    target_count = 0
    for row in plan['sources']:
        if set(row) != {'path', 'bytes', 'sha256', 'python35_target'}:
            raise ValueError('source_manifest_row_invalid')
        path = row['path']
        if type(path) is not str or path.startswith('/') or '..' in path.split('/') or ':' in path or '\\' in path:
            raise ValueError('source_manifest_path_invalid')
        if path in values or type(row['python35_target']) is not bool:
            raise ValueError('source_manifest_inventory_invalid')
        raw = fixed(BASE / path, (row['bytes'], row['sha256']))
        if row['python35_target']:
            ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
            target_count += 1
        values[path] = raw
    if len(values) != 11 or target_count != 7 or TEST not in values:
        raise ValueError('source_manifest_count_invalid')
    tree = ast.parse(values[TEST].decode('utf-8'))
    methods = [node.name + '.' + method.name for node in tree.body
               if isinstance(node, ast.ClassDef) for method in node.body
               if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')]
    if methods != [METHOD]:
        raise ValueError('unexpected_test_method')
    fixed(OPENSSL, OPENSSL_PIN)
    return values


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY no device arguments')
        return 2
    output = BASE / 'results' / ('sender-pump-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    private = output / 'private-inputs'
    source, rows, error = {}, [], None
    try:
        source = inputs()
        for path, raw in sorted(source.items()):
            destination = private / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            if destination.read_bytes() != raw:
                raise ValueError('snapshot_changed')
            rows.append(dict(path=path, bytes=len(raw), sha256=sha(raw)))
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, SyntaxError):
        error = 'source_or_snapshot_invalid'
    started = time.monotonic()
    stdout, stderr, exit_code, invoked, timeout = b'', b'', None, False, False
    if error is None:
        environment = dict(os.environ)
        environment.pop('PYTHONPATH', None)
        environment.pop('PYTHONSTARTUP', None)
        try:
            child = subprocess.run([sys.executable, '-I', '-B', str(private / TEST), '-q'],
                cwd=str(private), env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=90, check=False)
            stdout, stderr, exit_code, invoked = child.stdout, child.stderr, child.returncode, True
        except subprocess.TimeoutExpired as failure:
            stdout, stderr, invoked, timeout = failure.stdout or b'', failure.stderr or b'', True, True
        except OSError:
            error = 'child_not_started'
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    preserved = bool(source)
    for path, raw in source.items():
        try:
            preserved = (BASE / path).read_bytes() == raw and preserved
        except OSError:
            preserved = False
    try:
        fixed(OPENSSL, OPENSSL_PIN)
        openssl_preserved = True
    except (OSError, ValueError):
        openssl_preserved = False
    marker_ok = stdout in (MARKER, MARKER.replace(b'\n', b'\r\n'))
    summary_ok = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = bool(error is None and invoked and not timeout and exit_code == 0 and
                  preserved and openssl_preserved and marker_ok and summary_ok)
    value = dict(schema='sender-pump-host', passed=passed, verification_error=error,
        inputs=rows, input_snapshot_count=len(rows), sources_preserved=preserved,
        runtime_python35_ast=bool(source), runtime_source_count=7, new_method=METHOD,
        child_invocations=int(invoked), old_methods_invoked=0, child_exit=exit_code,
        child_timeout=timeout, elapsed_seconds=elapsed,
        stdout_bytes=len(stdout), stdout_sha256=sha(stdout), stderr_bytes=len(stderr), stderr_sha256=sha(stderr),
        fixed_marker_verified=marker_ok, unittest_summary_verified=summary_ok,
        openssl_bytes=OPENSSL_PIN[0], openssl_sha256=OPENSSL_PIN[1], openssl_preserved=openssl_preserved,
        actual_host_file_preparation_tested=passed, actual_host_tls_tested=passed,
        host_cases_passed=6 if passed else None, simultaneous_ws_download_tested=passed,
        actual_linux_socket_ownership_tested=False, native_go_integration_tested=False,
        gatt_identity_tested=False, device_accessed=False, phone_tested=False,
        rf_requested=False, physical_restore_verified=False, candidate_deployed=False,
        send_available=False, receive_available=False)
    result = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'PC-only actual FileRegistry selection, prepared ZIP and generated HOST TLS. '
        b'Six new loopback scenarios: normal, partial writes, peer cancel, early completion, '
        b'task mismatch, timeout. One simulated-phone thread; server pump stays on original worker. '
        b'TLS/HTTP/WebSocket and file bytes are actual HOST operations. '
        b'Not P011, Xiaomi, GATT, Linux native socket ownership, RF or physical restoration. '
        b'No old test methods are replayed. Keys/certificates and private failure raw are excluded. '
        b'Success raw is exported only after exact safe marker and Ran1/OK verification.\n')
    (output / 'result.json').write_bytes(result)
    (output / 'README.txt').write_bytes(readme)
    members = {'result.json': result, 'README.txt': readme}
    if passed:
        members.update({'stdout.raw': stdout, 'stderr.raw': stderr})
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in members.items():
            bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != list(members) or bundle.testzip() is not None or any(
                bundle.read(name) != raw for name, raw in members.items()):
            raise ValueError('public_zip_changed')
    print(json.dumps(dict(passed=passed, child_exit=exit_code, timeout=timeout,
        elapsed_seconds=elapsed, result_zip=str(archive), zip_sha256=sha(archive.read_bytes()))))
    return 0 if passed else 2 if error else 1


if __name__ == '__main__':
    sys.exit(main())
