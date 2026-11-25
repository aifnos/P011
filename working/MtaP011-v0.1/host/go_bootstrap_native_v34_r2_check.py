"""One isolated diagnostic r2 GO17 HOST model; no old-test invocation.

Only ROOT executes the first check. A private immutable 25-input snapshot feeds
one isolated child/method, no retry. The 120-second HOST wall cap bounds eleven
fresh explicit model flows; it does not change any original 300/20/10/60 native
period, quota, generation, or unknown-state gate. Linux/Proc/RF/Unix/fork/exec
are models; real PC source/ZIP bytes and archived WPA/stock-three inputs are
separate. The synthetic Python/CLI pins MUST NOT enter a device preparer.
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
import zlib

BASE = Path(__file__).resolve().parents[1]
CHECKER = 'host/go_bootstrap_native_v34_r2_check.py'
TEST = 'tests/test_go_bootstrap_native_v34_r2.py'
TEST_SHA = '3a674b7665f804fa1e666aa0acc123504cc2e61a54bdafc9cd5eb5bf11c76c40'
TEST_BYTES = 26001
METHOD = 'GoBootstrapNativeV34R2Tests.test_actual_go17_original_failures_diagnosed_preserving_loader_store_native_faults_and_restore'
MODEL = 'tests/go_bootstrap_host_model_v34.py'
MODEL_SHA = '97bb530656aa569f3677c66c24c3109651b7bfa5284c3de67459926ac5cf6155'
MODEL_BYTES = 25092
PLAN = 'host/go_bootstrap_native_v34_source_manifest.json'
PLAN_SHA = '491b08d4754fcbf5d3dc203c48cf73a5d274bf5fc4da7d46fbb41a3af55ea296'
PLAN_BYTES = 3952
CHILD_SECONDS = 120
EXPECTED_INPUTS = 25
MODULES = ('p011_json', 'mta_ip', 'mta_client_tmp_alias', 'mta_p2p_client_init',
    'mta_client_resource_budget', 'mta_client_proc', 'mta_client_journal_codec',
    'mta_client_coordination', 'mta_client_files', 'mta_client_pending', 'mta_client_store',
    'mta_go_process_owner', 'mta_go_deployment', 'mta_go_executor', 'mta_go_bootstrap_store',
    'mta_go_native', 'mta_go_bootstrap')
STOCK = (
    ('/usr/bin/Z03', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/Z03',
        'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a', 4103844),
    ('/usr/bin/control_engine', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/control_engine',
        '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d', 163184),
    ('/usr/bin/zyb_z03_launch.sh', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/zyb_z03_launch.sh',
        '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b', 1913))
WPA = ('native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant',
    'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301', 1351192)


def safe(path):
    return (type(path) is str and path and not path.startswith(('/', '\\')) and ':' not in path
        and '\\' not in path and all(p not in ('', '.', '..') for p in path.split('/')))


def fixed(path, sha, size):
    allowed_stock = {row[1] for row in STOCK}
    if not safe(path) and path not in allowed_stock: raise ValueError('input_path_changed')
    if type(size) is not int or not 1 <= size <= 8388608 or re.fullmatch('[0-9a-f]{64}', sha) is None:
        raise ValueError('input_identity_changed')
    raw = (BASE / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha: raise ValueError('input_changed')
    return raw


def add(inputs, path, raw):
    if path in inputs and inputs[path] != raw: raise ValueError('input_identity_conflict')
    inputs[path] = raw
    return raw


def verify(inputs):
    """SOURCE AST/hash only; no production/old tests are imported here."""
    raw_test = add(inputs, TEST, fixed(TEST, TEST_SHA, TEST_BYTES))
    raw_model = add(inputs, MODEL, fixed(MODEL, MODEL_SHA, MODEL_BYTES))
    plan = json.loads(add(inputs, PLAN, fixed(PLAN, PLAN_SHA, PLAN_BYTES)))
    if type(plan) is not dict or set(plan) != {'schema', 'sources'} or plan['schema'] != 'go-bootstrap-native-v34-host':
        raise ValueError('graph_changed')
    rows = plan['sources']
    if (type(rows) is not list or len(rows) != 17 or tuple(r['module'] for r in rows) != MODULES
            or any(set(r) != {'module', 'path', 'sha256', 'bytes'} for r in rows)):
        raise ValueError('graph_changed')
    graph = None
    for row in rows:
        raw = add(inputs, row['path'], fixed(row['path'], row['sha256'], row['bytes']))
        parsed = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if any(isinstance(n, ast.Assert) for n in ast.walk(parsed)): raise ValueError('target_assert_changed')
        if row['module'] == 'mta_go_deployment':
            graph = [ast.literal_eval(n.value) for n in parsed.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'MODULES' for t in n.targets)]
    if graph != [MODULES]: raise ValueError('loader_graph_changed')
    for path, relative, sha, size in STOCK: add(inputs, relative, fixed(relative, sha, size))
    add(inputs, WPA[0], fixed(*WPA))
    parsed = ast.parse(raw_test.decode('utf-8'))
    names = [cls.name + '.' + method.name for cls in parsed.body if isinstance(cls, ast.ClassDef)
        for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')]
    if names != [METHOD]: raise ValueError('method_changed')
    wanted = {'PLAN', 'PLAN_SHA', 'PLAN_BYTES', 'MODEL', 'MODEL_SHA', 'MODEL_BYTES', 'STOCK', 'WPA'}
    constants = {target.id: ast.literal_eval(n.value) for n in parsed.body if isinstance(n, ast.Assign)
        for target in n.targets if isinstance(target, ast.Name) and target.id in wanted}
    expected = dict(PLAN=PLAN, PLAN_SHA=PLAN_SHA, PLAN_BYTES=PLAN_BYTES, MODEL=MODEL,
        MODEL_SHA=MODEL_SHA, MODEL_BYTES=MODEL_BYTES, STOCK=STOCK, WPA=WPA)
    if constants != expected: raise ValueError('test_binding_changed')
    for tree in (parsed, ast.parse(raw_model.decode('utf-8'))):
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(a.name.startswith('test_') for a in node.names):
                raise ValueError('old_test_import')
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith(('test_', 'mta_', 'p011_')):
                raise ValueError('unexpected_fixture_import')
    if len(inputs) != EXPECTED_INPUTS: raise ValueError('input_inventory_changed')
    return rows


def snapshot(output, inputs):
    project = output / 'private-inputs' / 'project'
    working = project / 'working' / 'MtaP011-v0.1'
    observations = []
    for path, raw in sorted(inputs.items()):
        destination = (working / path).resolve()
        if not destination.is_relative_to(project.resolve()): raise ValueError('snapshot_escape')
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        if destination.read_bytes() != raw: raise ValueError('snapshot_changed')
        observations.append(dict(path=path, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    if len(observations) != EXPECTED_INPUTS: raise ValueError('snapshot_inventory_changed')
    return working, observations


def publish(output, value, stdout, stderr, passed):
    result = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (
        'One unique new fixed GO17 HOST algorithm method, eleven independent modeled flows. '
        'Actual fixed GoDeploymentLoader and original same-module F bootstrap/GoEntrySource execute; '
        'actual neutral Store/ProcReader/Budget, GO Store CAS/fsync/readback, original ChildOwner, '
        'Native netlink/Unix parsers/ACK/ECHO/caps/BSS/BI and bootstrap single-restore algorithms execute. '
        'No native/grant/canonical/typed Snapshot/restored boolean is injected. Existing constructor '
        'private IO seams are used through the original class/ctor, with creator identity retained. '
        'All Linux paths/FDs/OFDs/fork/exec/Proc/netlink/Unix credentials/clock/timeouts are explicit models. '
        'Valid ARM-shaped Python and CLI bytes are HOST-only synthetic identities, forbidden in a '
        'device preparer. Fixed WPA and stock-three archived bytes are actual PC inputs, not execution '
        'or current device identity proof. The 120s isolated child cap is only HOST wall time, no native '
        'active/preparation/cleanup period or quota is enlarged/renewed/refunded. '
        'Full ACK+ECHO type8->type9 and original baseline restore, missing ACK observation-without-ownership, '
        'independent child cleanup, closed raw/first unlink separation, unknown unlink no retry, delayed '
        'original endpoint vs foreign endpoint, and uncertain publication stop-only denial flows are modeled. '
        'Unknown canonical never authorizes GROUP_REMOVE/DELETE/marker clear; original cleanup tuple, '
        'budget/reader/epoch/mutex/cap, foreign source/ticket and expiry denial inputs grant no permission. '
        'No old test/checker/archived START/device/ADB/RF/phone is run. GO/IP/DHCP/TLS/send/receive service '
        'availability and actual P011 stock restore remain false, even after a HOST model success. '
        '25 immutable private source/binary inputs and original raw streams are retained once. Public raw '
        'is included only for exact fixed stdout marker, strict Ran1/OK stderr, child0 and no timeout. '
        'Failures publish only result/README; no automatic retry or raw rewriting.\n').encode('ascii')
    (output / 'result.json').write_bytes(result)
    (output / 'README.txt').write_bytes(readme)
    archive = output / 'public-result.zip'
    names = ['result.json', 'README.txt'] + (['stdout.raw', 'stderr.raw'] if passed else [])
    expected = {'result.json': result, 'README.txt': readme}
    if passed: expected.update({'stdout.raw': stdout, 'stderr.raw': stderr})
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name in names: bundle.writestr(name, expected[name])
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != names or bundle.testzip() is not None: raise ValueError('zip_changed')
        for name in names:
            raw, info = bundle.read(name), bundle.getinfo(name)
            if (raw != expected[name] or info.file_size != len(raw) or info.CRC != zlib.crc32(raw) & 0xffffffff
                    or (output / name).read_bytes() != raw): raise ValueError('zip_member_changed')
    return archive


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY fixed GO17 HOST model; no device/network/path arguments')
        return 2
    output = BASE / 'results' / ('go-bootstrap-native-v34-r2-model-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    own = Path(__file__).read_bytes()
    inputs, rows, source_verified = {CHECKER: own}, [], False
    verification_error = snapshot_error = launch_error = None
    try:
        rows = verify(inputs); source_verified = True
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, UnicodeError):
        verification_error = 'fixed_source_invalid'
    child_base, input_rows = None, []
    try: child_base, input_rows = snapshot(output, inputs)
    except (OSError, ValueError): snapshot_error = 'private_snapshot_invalid'
    complete = source_verified and snapshot_error is None
    stdout, stderr, code, timeout, invoked = b'', b'', None, False, False
    started = time.monotonic()
    if complete:
        env = dict(os.environ); env.pop('PYTHONPATH', None); env.pop('PYTHONSTARTUP', None)
        try:
            child = subprocess.run([sys.executable, '-I', '-B', str(child_base / TEST), '-q', METHOD],
                cwd=str(child_base), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=CHILD_SECONDS, check=False)
            stdout, stderr, code, invoked = child.stdout, child.stderr, child.returncode, True
        except subprocess.TimeoutExpired as error:
            stdout, stderr, timeout, invoked = error.stdout or b'', error.stderr or b'', True, True
        except OSError: launch_error = 'host_child_not_started'
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout); (output / 'stderr.raw').write_bytes(stderr)
    stdout_reviewed = stdout in (b'GO17_FULL_HOST_MODEL_R2_OK\n', b'GO17_FULL_HOST_MODEL_R2_OK\r\n')
    stderr_reviewed = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = complete and invoked and code == 0 and not timeout and stdout_reviewed and stderr_reviewed
    value = dict(schema='go-bootstrap-native-v34-r2-host', selected_method=METHOD, selected_method_count=1,
        new_method_invocations=int(invoked), old_test_method_invocations=0, old_wrapper_invocations=0,
        source_count=len(rows), sources=rows, source_manifest_sha256=PLAN_SHA, source_manifest_bytes=PLAN_BYTES,
        test_sha256=TEST_SHA, test_bytes=TEST_BYTES, model_sha256=MODEL_SHA, model_bytes=MODEL_BYTES,
        checker_sha256=hashlib.sha256(own).hexdigest(), source_integrity_verified=source_verified,
        python35_syntax_verified=source_verified, verification_error=verification_error,
        snapshot_error=snapshot_error, launch_error=launch_error, host_method_passed=passed,
        host_exit=code, timeout=timeout, host_child_timeout_seconds=CHILD_SECONDS, host_elapsed_seconds=elapsed,
        input_snapshot_complete=complete, input_snapshot_entry_count=len(input_rows), expected_input_snapshot_entry_count=EXPECTED_INPUTS,
        inputs=input_rows, child_reads_private_snapshot=invoked, child_python_isolated_mode=True,
        native_go17_algorithm_host_model_tested=passed, native_original_loader_entry_algorithm_host_model_tested=passed,
        native_store_cas_readback_and_process_owner_algorithm_host_model_tested=passed,
        native_ack_echo_caps_bss_bi_credential_parser_algorithm_host_model_tested=passed,
        native_same8_to9_and_single_restore_algorithm_host_model_tested=passed,
        fault_and_original_cap_deny_matrix_host_model_tested=passed,
        native_positive_grant_or_canonical_stubbed=False, restored_bool_stubbed=False,
        neutral_accounting_store_native_ctor=True, linux_io_proc_netlink_unix_clock_modeled=True,
        fork_exec_fd_ofd_signal_wait_and_ebadf_modeled=True, python_cli_executable_identities_modeled=True,
        actual_pc_pinned_wpa_and_stock3_byte_inputs=True, actual_pc_zip_bytes_crc_checked=True,
        real_device_python_cli_identity_tested=False, actual_wpa_or_python_exec_tested=False,
        actual_linux_proc_or_socket_tested=False, actual_native_fork_exec_signal_wait_tested=False,
        actual_physical_fd_or_endpoint_closure_tested=False, actual_linux_platform_pass=False,
        actual_child_branch_fd3_watchdog_loop_exercised=False,
        child_inherited_ofd_and_physical_lock_behavior_tested=False,
        notify_eof_or_R_actual_child_observed=False, modeled_child_parent_branch_only=True,
        original_quota_expanded=False, original_active_cap_renewed=False, unknown_resource_cleared=False,
        model_only_python_cli_pins_forbidden_in_device_preparer=True,
        state_production_receive_gate_enabled=False, p011_go_service_available=False,
        p011_ip_dhcp_tls_send_receive_available=False, actual_p011_restore_verified=False,
        device_accessed=False, rf_requested=False, phone_tested=False,
        private_key_or_user_id_public=False, raw_native_bytes_in_public_zip=False,
        full_syscall_wall_bound_verified=False, full_heap_bound_verified=False,
        stdout_fixed_marker_reviewed=stdout_reviewed, unittest_stderr_reviewed=stderr_reviewed,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        public_raw_included=passed, public_zip_member_count=4 if passed else 2)
    archive = publish(output, value, stdout, stderr, passed)
    print(json.dumps(dict(passed=passed, host_exit=code, timeout=timeout, elapsed_seconds=elapsed,
        result_zip=str(archive), zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())))
    return 0 if passed else 2 if verification_error or snapshot_error or launch_error else 1


if __name__ == '__main__': sys.exit(main())

