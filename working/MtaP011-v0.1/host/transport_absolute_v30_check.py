"""Fixed new PC-only component methods. Never native P011/RF/phone.

TLS method connects only to its fresh localhost sender; its scoped connector
is an explicit HOST seam, not a Linux SO_BINDTODEVICE/CLIENT owner proof.
Keep first raw failures private, exact source snapshots, and safe result ZIPs.
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
TEST = 'tests/test_transport_absolute_v30.py'
TEST_SHA = '036713ed8b664197618ae0228cf99f4293c50ac9a01720e044a0f9edbe324f86'
OLD_TRANSPORT = 'runtime/mta_transport.py'
OLD_SHA = '29e5ea6bf8f5de9ddae33824c158f4e401bab391d51b18dc0b8a1ab2cbc2dc72'
METHODS = {
    'bounds': ('TransportAbsoluteV30Tests.test_actual_socketpair_fixed_stream_timeout_expiry_regression_and_ctor_bounds', 30),
    'tls': ('TransportAbsoluteV30Tests.test_actual_local_tls_two_handoffs_bytes_and_late_confirmation_rejection', 90),
}


def passed_raw(code, timeout, stdout, stderr):
    # HOST Python 3.12 emits these exact TLS-1.2 deprecations from the two
    # pinned native definitions. They are not P011 errors or test failures.
    allowed = {b'HOST-v30-absolute/mta_transport.py:541: DeprecationWarning: ssl.PROTOCOL_TLSv1_2 is deprecated',
               b'HOST-v30-absolute/mta_sender.py:206: DeprecationWarning: ssl.PROTOCOL_TLSv1_2 is deprecated'}
    lines = stderr.splitlines(keepends=True)
    seen = set()
    while lines and lines[0].rstrip(b'\r\n') in allowed:
        warning = lines.pop(0).rstrip(b'\r\n')
        if warning in seen:return False
        seen.add(warning)
    derived = b''.join(lines)
    return code == 0 and not timeout and stdout == b'' and re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', derived) is not None


def fixed(relative, pin):
    raw = (BASE / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('source_changed')
    return raw


def verify():
    test_raw = fixed(TEST, TEST_SHA)
    tree = ast.parse(test_raw.decode('utf-8'))
    constants = {target.id: node.value for node in tree.body if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name)}
    sources = ast.literal_eval(constants['SOURCE_PINS'])
    if len(sources) != 6 or tuple(row[0] for row in sources) != ('p011_json', 'mta_protocol', 'mta_storage', 'mta_files', 'mta_transport', 'mta_sender'):
        raise ValueError('graph_changed')
    fixture, fixture_sha = (ast.literal_eval(constants[key]) for key in ('FIXTURE_PATH', 'FIXTURE_SHA'))
    inputs = {TEST: test_raw, fixture: fixed(fixture, fixture_sha), OLD_TRANSPORT: fixed(OLD_TRANSPORT, OLD_SHA)}
    rows = []
    for name, relative, pin in sources:
        raw = fixed(relative, pin)
        ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        inputs[relative] = raw
        rows.append(dict(module=name, path=relative, sha256=pin, bytes=len(raw)))
    methods = [c.name + '.' + m.name for c in tree.body if isinstance(c, ast.ClassDef)
        for m in c.body if isinstance(m, ast.FunctionDef) and m.name.startswith('test_')]
    if set(methods) != {entry[0] for entry in METHODS.values()} or len(methods) != 2:
        raise ValueError('method_changed')
    return rows, inputs


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in METHODS:
        print('PC_ONLY: choose fixed bounds or tls method; no device/path arguments')
        return 2
    stage = sys.argv[1]
    try: rows, inputs = verify()
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, UnicodeError):
        print('PC_ONLY_FAIL: fixed inputs invalid; no target method executed')
        return 2
    output = BASE / 'results' / ('transport-absolute-v30-' + stage + '-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    own_raw = Path(__file__).read_bytes()
    inputs['host/transport_absolute_v30_check.py'] = own_raw
    for relative, raw in inputs.items():
        destination = output / 'private-inputs' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    method, cap = METHODS[stage]
    started, timeout = time.monotonic(), False
    try:
        child = subprocess.run([sys.executable, '-B', str(BASE / TEST), '-q', method],
            cwd=str(BASE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=cap, check=False)
        stdout, stderr, code = child.stdout, child.stderr, child.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code, timeout = error.stdout or b'', error.stderr or b'', None, True
    duration = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    passed = passed_raw(code, timeout, stdout, stderr)
    value = dict(schema='transport-absolute-v30-host', stage=stage, test_sha256=TEST_SHA,
        selected_method=method, selected_method_count=1, host_exit=code, timeout=timeout,
        host_elapsed_seconds=duration, host_method_passed=passed, sources=rows,
        source_integrity_verified=True, python35_syntax_verified=True, old_transport_preserved=True,
        actual_local_tls_file_method_completed=passed and stage == 'tls',
        socketpair_clock_boundary_method_completed=passed and stage == 'bounds',
        model='actual localhost transport/storage/TLS with HOST-only connector; synthetic clock negative boundaries',
        native_client_capsule_tested=False, production_f_integrated=False, device_accessed=False,
        rf_requested=False, actual_p011_endpoint_verified=False, actual_p011_restore_verified=False,
        p011_send_available=False, p011_receive_available=False, phone_tested=False,
        full_syscall_wall_bound_verified=False, full_heap_bound_verified=False,
        checker_sha256=hashlib.sha256(own_raw).hexdigest(), stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(), public_raw_included=passed)
    raw = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
    note = b'PC components only. Actual local TLS/files do not prove P011 scoped CLIENT, F, RF, recovery or Xiaomi interop. Synthetic clock boundaries are not whole syscall/heap guarantees. Old methods not rerun. Failed raw/private keys/source snapshots remain private.\n'
    (output / 'result.json').write_bytes(raw)
    (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', raw); bundle.writestr('README.txt', note)
        if passed:
            bundle.writestr('stdout.raw', stdout); bundle.writestr('stderr.raw', stderr)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None or bundle.read('result.json') != raw:
            raise ValueError('archive_changed')
    print(json.dumps(dict(stage=stage, passed=passed, host_exit=code, timeout=timeout,
        elapsed_seconds=duration, result_zip=str(archive), zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()), ensure_ascii=False))
    return 0 if passed else 1


if __name__ == '__main__': raise SystemExit(main())
