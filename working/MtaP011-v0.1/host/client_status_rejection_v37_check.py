"""Fixed unique small v37 STATUS pre-dispatch rejection PC-only check.

Private snapshots contain the 35 source definitions, selected test, manifest
and this checker only. No old fixtures/TestCase/checker/ELF is executed. This
does not invoke full F/Parent/State/INIT/transfer or certify any OS/RF/close.
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
CHECKER = 'host/client_status_rejection_v37_check.py'
TEST = 'tests/test_client_status_rejection_v37.py'
TEST_SHA = 'c930096d708d1188cca0ccbf472c12bf582a9c8c95137c4cce16be3b98fb4671'
TEST_BYTES = 10460
METHOD = 'ClientStatusRejectionV37Tests.test_native_status_predispatch_rejections_and_failed_claim_are_io_free'
PLAN = 'host/client_integrated_v37_source_manifest.json'
PLAN_SHA = '4b9ea54997194ca895a3459cf88cd715b2ccc05e46c55b533920f8182314d07a'
PLAN_BYTES = 8077
PREVIOUS_PLAN_SHA = '2b13ba05acb3dd4984f7d2c5740349f4d90f1980ebde4014aa63f62a515f721a'
CHILD_SECONDS = 30
EXPECTED_SNAPSHOT_INPUTS = 38


def safe_relative(path):
    return (type(path) is str and bool(path) and not path.startswith(('/', '\\')) and
        '\\' not in path and ':' not in path and
        all(part not in ('', '.', '..') for part in path.split('/')))


def fixed(path, sha, size):
    if (not safe_relative(path) or type(size) is not int or not 1 <= size <= 8388608 or
            type(sha) is not str or re.fullmatch('[0-9a-f]{64}', sha) is None):
        raise ValueError('source_changed')
    raw = (BASE / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('source_changed')
    return raw


def add(inputs, path, raw):
    if path in inputs and inputs[path] != raw: raise ValueError('input_identity_conflict')
    inputs[path] = raw
    return raw


def verify(inputs):
    """AST/hash SOURCE verification only; no target/old-test imports."""
    test_raw = add(inputs, TEST, fixed(TEST, TEST_SHA, TEST_BYTES))
    plan_raw = add(inputs, PLAN, fixed(PLAN, PLAN_SHA, PLAN_BYTES))
    plan = json.loads(plan_raw)
    if (type(plan) is not dict or set(plan) != {'schema', 'previous_manifest_sha256', 'sources'} or
            plan['schema'] != 'client-integrated-v37-host' or
            plan['previous_manifest_sha256'] != PREVIOUS_PLAN_SHA or type(plan['sources']) is not list):
        raise ValueError('graph_changed')
    rows = plan['sources']
    if (len(rows) != 35 or any(type(row) is not dict or set(row) != {'module', 'path', 'sha256', 'bytes'}
            for row in rows) or len({row['module'] for row in rows}) != 35):
        raise ValueError('graph_changed')
    graph = None
    for row in rows:
        name = row['module']
        if type(name) is not str or re.fullmatch('(?:mta_|p011_)[a-z0-9_]+', name) is None:
            raise ValueError('graph_changed')
        raw = add(inputs, row['path'], fixed(row['path'], row['sha256'], row['bytes']))
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('target_assert_changed')
        if name == 'mta_client_executor':
            graph = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'MODULES' for t in node.targets)]
    if graph != [tuple(row['module'] for row in rows)]: raise ValueError('executor_graph_changed')
    tree = ast.parse(test_raw.decode('utf-8'))
    methods = [cls.name + '.' + method.name for cls in tree.body if isinstance(cls, ast.ClassDef)
        for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')]
    if methods != [METHOD]: raise ValueError('method_changed')
    names = {'PLAN', 'PLAN_SHA', 'PLAN_BYTES', 'PREVIOUS_PLAN_SHA'}
    constants = {target.id: ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name) and target.id in names}
    if constants != dict(PLAN=PLAN, PLAN_SHA=PLAN_SHA, PLAN_BYTES=PLAN_BYTES, PREVIOUS_PLAN_SHA=PREVIOUS_PLAN_SHA):
        raise ValueError('test_source_binding_changed')
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(alias.name.startswith('test_') for alias in node.names):
            raise ValueError('legacy_test_import')
        if isinstance(node, ast.ImportFrom) and node.module is not None and node.module.startswith('test_'):
            raise ValueError('legacy_test_import')
    if len(inputs) != EXPECTED_SNAPSHOT_INPUTS: raise ValueError('input_inventory_changed')
    return rows


def snapshot_inputs(output, inputs):
    child_base = output / 'private-inputs' / 'working'
    observations = []
    for path, raw in sorted(inputs.items()):
        destination = child_base / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        saved = destination.read_bytes()
        if saved != raw: raise ValueError('snapshot_changed')
        observations.append(dict(path=path, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    if len(observations) != EXPECTED_SNAPSHOT_INPUTS: raise ValueError('snapshot_inventory_changed')
    return child_base, observations


def publish(output, value, stdout, stderr, passed):
    result = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (
        'One unique new v37 native STATUS pre-dispatch rejection HOST method only, from fixed private bytes. '
        'The 35 fixed modules are definitions; Provider(None) pure construction and receive/channel/current '
        'native front guards execute on explicit tripwire IO. No old tests, fixtures or checker are imported/run. '
        'Nonactive/copy/claimed/bool-short-send and exact poll/reply/event rejection must precede native full context, '
        'anchors, timeout, clock and IO. Invalid-active dictionaries are denial inputs only: there is no original '
        'issuer-history membership, Store, Journal, active context, FD or readiness. The failed-once-claim case '
        'executes the actual claimed transition and issuer-history rejection; a retry cannot reset/reclaim it. '
        'This does not test valid live issuance, active expiry/held-mutex continuity, recv faults, finally revoke, '
        'actual OS/TCP/TLS, complete F/Parent/State business, resource-budget cleanup, close, restore or RF. '
        'Production admission remains disabled; no P011/phone or send/receive availability is certified. '
        'No quota, cap, history membership or unknown state is expanded/renewed/washed clean. '
        'Public raw requires empty stdout, exact Ran1/OK stderr, child0 and no timeout. Failure raw and '
        '38 immutable private inputs are retained privately with no automatic retry/reconciliation.\n'
    ).encode('ascii')
    (output / 'result.json').write_bytes(result)
    (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    members = ['result.json', 'README.txt'] + (['stdout.raw', 'stderr.raw'] if passed else [])
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', result)
        bundle.writestr('README.txt', note)
        if passed:
            bundle.writestr('stdout.raw', stdout)
            bundle.writestr('stderr.raw', stderr)
    with zipfile.ZipFile(archive) as bundle:
        if (bundle.namelist() != members or bundle.testzip() is not None or
                bundle.read('result.json') != result or bundle.read('README.txt') != note or
                passed and (bundle.read('stdout.raw') != stdout or bundle.read('stderr.raw') != stderr)):
            raise ValueError('archive_changed')
    return archive


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY: fixed one new v37 STATUS rejection method; no device/path/network arguments')
        return 2
    output = BASE / 'results' / ('client-status-rejection-v37-native-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    own = Path(__file__).read_bytes()
    inputs, rows = {CHECKER: own}, []
    source_verified, verification_error = False, None
    verification_started = time.monotonic()
    try:
        rows = verify(inputs)
        source_verified = True
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, UnicodeError):
        verification_error = 'fixed_source_invalid'
    verification_seconds = time.monotonic() - verification_started
    snapshot_error, child_base, input_rows = None, None, []
    try:
        child_base, input_rows = snapshot_inputs(output, inputs)
    except (OSError, ValueError):
        snapshot_error = 'private_snapshot_invalid'
    snapshot_complete = source_verified and snapshot_error is None
    stdout, stderr, code, timeout = b'', b'', None, False
    attempted, invoked, launch_error = False, False, None
    started = time.monotonic()
    if snapshot_complete:
        attempted = True
        child_env = dict(os.environ)
        child_env.pop('PYTHONPATH', None)
        child_env.pop('PYTHONSTARTUP', None)
        try:
            child = subprocess.run([sys.executable, '-I', '-B', str(child_base / TEST), '-q', METHOD],
                cwd=str(child_base), env=child_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=CHILD_SECONDS, check=False)
            stdout, stderr, code, invoked = child.stdout, child.stderr, child.returncode, True
        except subprocess.TimeoutExpired as error:
            stdout, stderr, timeout, invoked = error.stdout or b'', error.stderr or b'', True, True
        except OSError:
            launch_error = 'host_child_not_started'
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    stderr_reviewed = re.fullmatch(
        rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = (invoked and snapshot_complete and launch_error is None and code == 0 and
        not timeout and stdout == b'' and stderr_reviewed)
    value = dict(schema='client-status-rejection-v37-host', selected_method=METHOD,
        selected_method_count=1, old_test_method_invocations=0, old_wrapper_invocations=0,
        new_method_invocations=1 if invoked else 0, method_attempted=attempted, method_invoked=invoked,
        host_exit=code, timeout=timeout, host_child_timeout_seconds=CHILD_SECONDS, host_elapsed_seconds=elapsed,
        source_verification_elapsed_seconds=verification_seconds, verification_error=verification_error,
        snapshot_error=snapshot_error, launch_error=launch_error, host_method_passed=passed,
        source_integrity_verified=source_verified, python35_syntax_verified=source_verified,
        source_count=len(rows), sources=rows, source_manifest_sha256=PLAN_SHA, source_manifest_bytes=PLAN_BYTES,
        previous_source_manifest_sha256=PREVIOUS_PLAN_SHA, test_sha256=TEST_SHA, test_bytes=TEST_BYTES,
        checker_sha256=hashlib.sha256(own).hexdigest(), input_snapshot_complete=snapshot_complete,
        input_snapshot_entry_count=len(input_rows), expected_input_snapshot_entry_count=EXPECTED_SNAPSHOT_INPUTS,
        inputs=input_rows, child_reads_private_snapshot=invoked, child_python_isolated_mode=True,
        native_graph_definition_count=35 if passed else None, legacy_fixture_input_count=0,
        native_provider_none_ctor_host_tested=passed, native_status_front_rejection_host_tested=passed,
        native_failed_claim_not_reset_host_tested=passed,
        native_algorithm_scope='pure_constructor_and_predispatch_denial_only',
        invalid_active_is_deny_fixture_only=True, native_positive_ticket_issued=False,
        native_status_context_full_called=False if passed else None,
        native_status_recv_called=False if passed else None,
        valid_live_ticket_tested=False, active_ticket_expiry_tested=False, held_mutex_continuity_tested=False,
        receive_fault_finally_revoke_tested=False, native_ready_fact_issued=False, native_close_proof_issued=False,
        quota_expanded=False, active_cap_renewed=False, unknown_cleared=False,
        full_35_algorithm_receive_tested=False, actual_f_executor_run_tested=False,
        full_state_receive_business_tested=False, deployment_loader_tested=False,
        actual_parent_spawn_wait_tested=False, actual_parent_admission_tested=False,
        actual_pc_worker_task_tested=False, actual_parent_fifo_tested=False,
        actual_tcp_tls_tested=False, actual_linux_platform_tested=False,
        runtime_io_tripwire=True, runtime_clock_input_model=True, state_production_receive_gate_enabled=False,
        device_accessed=False, rf_requested=False, phone_tested=False,
        p011_send_available=False, p011_receive_available=False, actual_p011_restore_verified=False,
        private_binary_or_certificate_key_inputs=False, native_binary_bytes_in_public_zip=False,
        full_syscall_wall_bound_verified=False, full_heap_bound_verified=False,
        stdout_empty_reviewed=stdout == b'', unittest_stderr_reviewed=stderr_reviewed,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        public_raw_included=passed, public_zip_member_count=4 if passed else 2)
    archive = publish(output, value, stdout, stderr, passed)
    print(json.dumps(dict(selected_method=METHOD, passed=passed, host_exit=code, timeout=timeout,
        elapsed_seconds=elapsed, public_zip_member_count=4 if passed else 2,
        result_zip=str(archive), zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())))
    return 0 if passed else 2 if verification_error or snapshot_error or launch_error else 1


if __name__ == '__main__': sys.exit(main())
