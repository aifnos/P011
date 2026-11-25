"""Fixed PC helper checks; no device, RF, child launch or native CLIENT grant."""
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
HELPER = 'tests/test_client_transfer_boundaries_v30.py'
HELPER_SHA = '2ded97aeed6d0273164e9410ec19d1b69ad057d30dd4ad3c9e24bb2367aacbf9'
PASSIVE = 'tests/test_client_owner_passive_v30.py'
PASSIVE_SHA = 'f55693f34cb67e550b8665e97dacbce74d9bc0099351458e7837774bf84c6244'
METHODS = {
    'dispose': (HELPER, 'ClientTransferBoundariesV30Tests.test_native_dispose_original_fixed_cap_actual_pipe_ebadf_once'),
    'early': (HELPER, 'ClientTransferBoundariesV30Tests.test_native_full_early_refusal_without_route_constructor_is_zero_resource'),
    'passive': (PASSIVE, 'ClientOwnerPassiveV30Tests.test_native_passive_bad_or_late_fifo_stops_without_poisoning_known_fd_onceclose'),
}


def fixed(path, sha, size=None):
    raw = (BASE / path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha or size is not None and len(raw) != size:
        raise ValueError('source_changed')
    return raw


def verify():
    inputs = {HELPER: fixed(HELPER, HELPER_SHA), PASSIVE: fixed(PASSIVE, PASSIVE_SHA)}
    tree = ast.parse(inputs[HELPER].decode('utf-8'))
    constants = {t.id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                 for t in n.targets if isinstance(t, ast.Name) and t.id in
                 ('MANIFEST_PATH', 'MANIFEST_SHA', 'REPLACEMENTS', 'APPENDED')}
    manifest = constants['MANIFEST_PATH']
    inputs[manifest] = fixed(manifest, constants['MANIFEST_SHA'])
    rows = json.loads(inputs[manifest])['sources']
    if len(rows) != 31 or len({r['module'] for r in rows}) != 31: raise ValueError('graph_changed')
    result = []
    for row in rows:
        path, sha, size = constants['REPLACEMENTS'].get(row['module'], (row['path'], row['sha256'], row['bytes']))
        result.append(dict(module=row['module'], path=path, sha256=sha, bytes=size))
    for name, path, sha, size in constants['APPENDED']:
        result.append(dict(module=name, path=path, sha256=sha, bytes=size))
    if len(result) != 35 or len({r['module'] for r in result}) != 35: raise ValueError('graph_changed')
    for row in result:
        raw = fixed(row['path'], row['sha256'], row['bytes'])
        ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        inputs[row['path']] = raw
    found = set()
    for path in (HELPER, PASSIVE):
        tree = ast.parse(inputs[path].decode('utf-8'))
        found.update((path, c.name + '.' + m.name) for c in tree.body if isinstance(c, ast.ClassDef)
                     for m in c.body if isinstance(m, ast.FunctionDef) and m.name.startswith('test_'))
    if found != set(METHODS.values()): raise ValueError('method_changed')
    passive_constants = {t.id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                         for t in n.targets if isinstance(t, ast.Name) and t.id in ('DEFINITION_PATH', 'DEFINITION_SHA')}
    if passive_constants != {'DEFINITION_PATH': HELPER, 'DEFINITION_SHA': HELPER_SHA}: raise ValueError('helper_changed')
    return result, inputs


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in METHODS:
        print('PC_ONLY: choose dispose, early or passive; no target/path arguments')
        return 2
    stage = sys.argv[1]
    try: rows, inputs = verify()
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, UnicodeError):
        print('PC_ONLY_FAIL: fixed source invalid; no method executed')
        return 2
    output = BASE / 'results' / ('client-transfer-v30-r2-' + stage + '-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    own = Path(__file__).read_bytes()
    inputs['host/client_transfer_boundaries_v30_check.py'] = own
    for path, raw in inputs.items():
        destination = output / 'private-inputs' / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    test, method = METHODS[stage]
    started, timeout = time.monotonic(), False
    try:
        child = subprocess.run([sys.executable, '-B', str(BASE / test), '-q', method],
            cwd=str(BASE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        stdout, stderr, code = child.stdout, child.stderr, child.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code, timeout = error.stdout or b'', error.stderr or b'', None, True
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout); (output / 'stderr.raw').write_bytes(stderr)
    passed = code == 0 and not timeout and stdout == b'' and re.fullmatch(
        rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    value = dict(schema='client-transfer-v30-r2-helper-host', stage=stage, selected_method=method,
        selected_method_count=1, host_exit=code, timeout=timeout, host_elapsed_seconds=elapsed,
        host_method_passed=passed, sources=rows, source_integrity_verified=True,
        python35_syntax_verified=True, actual_pc_pipe_io_tested=passed and stage in ('dispose', 'passive'),
        synthetic_socket_kind_seam=stage == 'dispose', synthetic_clock_boundaries=True,
        modeled_actor_prerequisites=stage == 'passive', actual_socket_identity_tested=False,
        native_client_capsule_tested=False, native_f_lifecycle_tested=False, device_accessed=False,
        rf_requested=False, phone_tested=False, actual_p011_endpoint_verified=False,
        actual_p011_restore_verified=False, p011_send_available=False, p011_receive_available=False,
        full_syscall_wall_bound_verified=False, full_heap_bound_verified=False,
        checker_sha256=hashlib.sha256(own).hexdigest(), stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(), public_raw_included=passed)
    raw = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
    note = b'PC helper checks only. Actual pipe IO uses synthetic clock; dispose additionally models only socket-kind metadata. Passive Actor prerequisites are modeled, not launched/reaped children. No F lifecycle, P011, RF, TCP permission, phone, wall/heap or recovery pass. Failed raw and source snapshots remain private. Old passed methods not rerun.\n'
    (output / 'result.json').write_bytes(raw); (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', raw); bundle.writestr('README.txt', note)
        if passed:
            bundle.writestr('stdout.raw', stdout); bundle.writestr('stderr.raw', stderr)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None or bundle.read('result.json') != raw: raise ValueError('archive_changed')
    print(json.dumps(dict(stage=stage, passed=passed, host_exit=code, timeout=timeout,
        elapsed_seconds=elapsed, result_zip=str(archive), zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()), ensure_ascii=False))
    return 0 if passed else 1


if __name__ == '__main__': raise SystemExit(main())
