"""New PC typed IPC checks. Never F lifecycle, network or device execution."""
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
TEST = 'tests/test_client_receive_ipc_v31.py'
TEST_SHA = '6153f9b9719e2f369481462cbdd3c4442f8b0041b361ada701387b84e25e52fe'
PLAN = 'host/client_transfer_executor_v31_source_manifest.json'
PLAN_SHA = '35e6f1ba210f9fbd476f866c35e66b01c8d707dea017beae067c6f75d4b2fc9a'
METHODS = {
    'codec': 'ReceiveIpcV31Tests.test_codec_canonical_once_true_false_cancel_eof_and_wrong_original',
    'decision': 'ReceiveIpcV31Tests.test_parent_original_prompt_true_false_short_write_and_original_deadline',
    'rejection': 'ReceiveIpcV31Tests.test_parent_wrong_binding_sequence_task_replay_and_no_restore_proof',
    'progress': 'ReceiveIpcV31Tests.test_parent_fragmented_private_progress_result_and_refusal_preserve_public_flags',
}


def fixed(path, sha, size=None):
    raw = (BASE / path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha or size is not None and len(raw) != size:
        raise ValueError('source_changed')
    return raw


def verify():
    inputs = {TEST: fixed(TEST, TEST_SHA), PLAN: fixed(PLAN, PLAN_SHA, 8081)}
    plan = json.loads(inputs[PLAN]); rows = plan['sources']
    if plan['schema'] != 'client-transfer-executor-v31-host' or len(rows) != 35 or len({r['module'] for r in rows}) != 35:
        raise ValueError('graph_changed')
    for row in rows:
        raw = fixed(row['path'], row['sha256'], row['bytes'])
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        inputs[row['path']] = raw
        if row['module'] == 'mta_client_executor':
            graph = [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and
                     any(isinstance(t, ast.Name) and t.id == 'MODULES' for t in n.targets)]
            if graph != [tuple(r['module'] for r in rows)]: raise ValueError('executor_graph_changed')
    tree = ast.parse(inputs[TEST].decode('utf-8'))
    methods = [c.name + '.' + m.name for c in tree.body if isinstance(c, ast.ClassDef)
               for m in c.body if isinstance(m, ast.FunctionDef) and m.name.startswith('test_')]
    if len(methods) != 4 or set(methods) != set(METHODS.values()): raise ValueError('method_changed')
    constants = {t.id: ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                 for t in n.targets if isinstance(t, ast.Name) and t.id in ('MANIFEST', 'MANIFEST_SHA', 'SOURCES')}
    if constants['MANIFEST'] != PLAN or constants['MANIFEST_SHA'] != PLAN_SHA: raise ValueError('manifest_changed')
    actual = constants['SOURCES']
    if tuple(r[0] for r in actual) != ('p011_json', 'mta_protocol', 'mta_client_control_frame', 'mta_client_executor'):
        raise ValueError('executed_definition_scope_changed')
    mapped = {r['module']: r for r in rows}
    if any(mapped[n]['path'] != p or mapped[n]['sha256'] != s for n, p, s in actual): raise ValueError('source_changed')
    return rows, inputs


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in METHODS:
        print('PC_ONLY: choose codec, decision, rejection or progress; no device/path arguments')
        return 2
    stage = sys.argv[1]
    try: rows, inputs = verify()
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, UnicodeError):
        print('PC_ONLY_FAIL: fixed source invalid; no method executed')
        return 2
    output = BASE / 'results' / ('client-receive-ipc-v31-' + stage + '-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir(); own = Path(__file__).read_bytes()
    inputs['host/client_receive_ipc_v31_check.py'] = own
    for path, raw in inputs.items():
        destination = output / 'private-inputs' / path
        destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(raw)
    started, timeout = time.monotonic(), False
    try:
        child = subprocess.run([sys.executable, '-B', str(BASE / TEST), '-q', METHODS[stage]],
            cwd=str(BASE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
        stdout, stderr, code = child.stdout, child.stderr, child.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code, timeout = error.stdout or b'', error.stderr or b'', None, True
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout); (output / 'stderr.raw').write_bytes(stderr)
    passed = code == 0 and not timeout and stdout == b'' and re.fullmatch(
        rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    value = dict(schema='client-receive-ipc-v31-host', stage=stage, selected_method=METHODS[stage],
        selected_method_count=1, host_exit=code, timeout=timeout, host_elapsed_seconds=elapsed,
        host_method_passed=passed, sources=rows, source_integrity_verified=True,
        python35_syntax_verified=True, source_manifest_sha256=PLAN_SHA, test_sha256=TEST_SHA,
        source_count=35, executed_definition_count=4, actual_parent_fifo_tested=False,
        host_typed_ipc_tested=passed, modeled_parent_admission_and_pipe=True, synthetic_clock=True,
        native_f_lifecycle_tested=False, deployment_loader_tested=False, device_accessed=False,
        rf_requested=False, phone_tested=False, p011_send_available=False, p011_receive_available=False,
        actual_p011_restore_verified=False, actual_file_transfer_tested=False,
        full_syscall_wall_bound_verified=False, full_heap_bound_verified=False,
        checker_sha256=hashlib.sha256(own).hexdigest(), stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(), public_raw_included=passed)
    raw = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
    note = b'PC typed file-consent IPC only. Four native definitions execute over fictional admitted Parent/process/FIFO and synthetic clock. Not Loader, original F lifecycle, BLE/RF, transfer, restoration, P011 or Xiaomi acceptance. Failed raw/source snapshots stay private. Old passed methods not rerun.\n'
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
