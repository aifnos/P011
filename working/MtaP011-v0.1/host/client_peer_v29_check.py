"""Fixed PC-only peer methods, original raw results, no device entry point.

The 31-source model adds the peer via an explicit fixture seam. Production F's
30-source loader/peer creation is not integrated or approved by these checks.
No old TestCase methods execute. Failure raw remains private and unchanged.
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
PLAN = 'host/client_peer_v29_source_manifest.json'
PLAN_SHA = 'e0ba531ecc464c6bec39bdec8ec06077ba48910cf99387a497b67b5bdd4a18c3'
OLD_PLAN = 'host/client_session_v28_r2_source_manifest.json'
OLD_SHA = '154f6fd68dfecd3e8efd7080680a61a7703fd97e862f9464c105ae50d2f5c820'
TEST = 'tests/test_client_peer_v29.py'
TEST_SHA = '2ac029e895505c2e6117ddbf33ff69f72fe7c7b4f77bf73110671db8a51f4da1'
CHANGED = frozenset(('mta_client_linux_provider', 'mta_client_store'))
METHODS = {
    'codec': ('ClientPeerV29Tests.test_pure_neighbor_collector_absent_unresolved_and_poisoned_frames', 30),
    'native': ('ClientPeerV29Tests.test_native_peer_after_applied_ip_explicit_fixture_seam_and_single_cleanup', 300),
}


def fixed(relative, pin, size=None):
    raw = (BASE / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin or size is not None and len(raw) != size:
        raise ValueError('fixed_input_changed')
    return raw


def verify():
    plan_raw, old_raw = fixed(PLAN, PLAN_SHA), fixed(OLD_PLAN, OLD_SHA)
    plan, old = json.loads(plan_raw), json.loads(old_raw)['sources']
    if set(plan) != {'schema', 'previous_manifest_sha256', 'sources'} or plan['schema'] != 'client-peer-v29-host' or plan['previous_manifest_sha256'] != OLD_SHA:
        raise ValueError('plan_changed')
    rows = plan['sources']
    if len(rows) != 31 or [r['module'] for r in rows] != [r['module'] for r in old] + ['mta_client_peer']:
        raise ValueError('graph_changed')
    inputs = {PLAN: plan_raw, OLD_PLAN: old_raw}
    for row, previous in zip(rows, old):
        inputs[previous['path']] = fixed(previous['path'], previous['sha256'], previous['bytes'])
        if row['module'] not in CHANGED and row != previous:
            raise ValueError('previous_row_changed')
    for row in rows:
        if set(row) != {'module', 'path', 'sha256', 'bytes'}:
            raise ValueError('row_changed')
        if row['module'] in CHANGED | {'mta_client_peer'} and row['path'] != 'candidate/client-peer-v29-r2/runtime/' + row['module'] + '.py':
            raise ValueError('candidate_path_changed')
        raw = fixed(row['path'], row['sha256'], row['bytes'])
        inputs[row['path']] = raw
        tree = ast.parse(raw.decode('utf-8'), filename=row['path'], feature_version=(3, 5))
        if any(isinstance(n, ast.Assert) for n in ast.walk(tree)):
            raise ValueError('target_assert')
        if row['module'] == 'mta_client_executor':
            constants = [n.value for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'MODULES' for t in n.targets)]
            if len(constants) != 1 or ast.literal_eval(constants[0]) != tuple(r['module'] for r in old):
                raise ValueError('prior_f_graph_changed')
    raw = fixed(TEST, TEST_SHA)
    inputs[TEST] = raw
    tree = ast.parse(raw.decode('utf-8'), filename=TEST)
    methods = [c.name + '.' + m.name for c in tree.body if isinstance(c, ast.ClassDef) for m in c.body if isinstance(m, ast.FunctionDef) and m.name.startswith('test_')]
    if set(methods) != {value[0] for value in METHODS.values()} or len(methods) != 2:
        raise ValueError('method_scope_changed')
    # Preserve the unchanged fixture sources too. These files define models;
    # their old TestCase methods are not selected by this runner.
    for relative in ('tests/test_client_actual_collector_v25.py', 'tests/test_client_durable_connect_v19.py', 'tests/test_client_proc.py', 'tests/test_client_process_owner.py'):
        inputs[relative] = (BASE / relative).read_bytes()
    return rows, inputs


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in METHODS:
        print('PC_ONLY: choose fixed codec or native method; no device/path arguments')
        return 2
    stage = sys.argv[1]
    try:
        rows, inputs = verify()
    except (OSError, ValueError, TypeError, KeyError, SyntaxError, UnicodeError):
        print('PC_ONLY_FAIL: fixed inputs invalid; no target executed')
        return 2
    output = BASE / 'results' / ('client-peer-v29-' + stage + '-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    checker_raw = Path(__file__).read_bytes()
    inputs['host/client_peer_v29_check.py'] = checker_raw
    for relative, raw in inputs.items():
        destination = output / 'private-inputs' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    method, cap = METHODS[stage]
    before, timeout = time.monotonic(), False
    try:
        child = subprocess.run([sys.executable, '-B', str(BASE / TEST), '-q', method], cwd=str(BASE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=cap, check=False)
        stdout, stderr, code = child.stdout, child.stderr, child.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code, timeout = error.stdout or b'', error.stderr or b'', None, True
    duration = time.monotonic() - before
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    passed = code == 0 and not timeout and stdout == b'' and re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    value = dict(schema='client-peer-v29-host', stage=stage, source_manifest_sha256=PLAN_SHA,
        checker_sha256=hashlib.sha256(checker_raw).hexdigest(), source_count=31, sources=rows,
        source_integrity_verified=True, python35_syntax_verified=True, old_sources_preserved=True,
        selected_method=method, test_sha256=TEST_SHA, selected_method_count=1,
        host_exit=code, host_elapsed_seconds=duration, timeout=timeout, host_method_passed=passed,
        model='actual code with synthetic OS/kernel/clock; explicit fixture peer seam, not automatic production creation',
        modeled_native_peer_flow_completed=passed and stage == 'native',
        pure_codec_method_completed=passed and stage == 'codec', formal_loader_peer_graph_integrated=False,
        device_accessed=False, rf_requested=False, actual_linux_peer_observed=False,
        device_restoration_verified=False, actual_endpoint_verified=False,
        send_available=False, receive_available=False, phone_tested=False,
        full_syscall_wall_bound_verified=False, full_heap_bound_verified=False,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        public_raw_included=passed)
    raw = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
    note = b'PC model only. Production F peer loader/creation, TCP, real phone, RF and full wall/heap bounds NOT VERIFIED. Old cases not rerun. Failed raw and source snapshots stay private.\n'
    (output / 'result.json').write_bytes(raw)
    (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', raw)
        bundle.writestr('README.txt', note)
        if passed:
            bundle.writestr('stdout.raw', stdout)
            bundle.writestr('stderr.raw', stderr)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None or bundle.read('result.json') != raw or bundle.read('README.txt') != note:
            raise ValueError('archive_changed')
    print(json.dumps(dict(stage=stage, passed=passed, host_exit=code, timeout=timeout,
        elapsed_seconds=duration, result_zip=str(archive), zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()), ensure_ascii=False))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
