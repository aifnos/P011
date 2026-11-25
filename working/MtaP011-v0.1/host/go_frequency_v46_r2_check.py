"""Four new v46 first-baseline refusal checks; ROOT first execution only.

One immutable 26-input private snapshot feeds one isolated child/method, without
retry. The original seven-case first method remains FAIL; its three completed
partial cases and six event-parser negatives are not rerun or promoted here.
This method reaches the four baseline cases' previously unexecuted tail after
correcting only the immutable empty-history HOST expectation. The 120-second
HOST cap and all native quotas/periods/unknown gates stay unchanged. Linux/Proc/
FD/OFD/netlink/Unix/fork/exec/clock are models; PC pinned inputs/ZIP are actual.
Synthetic Python/CLI identities MUST NOT enter a real device preparer.
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
CHECKER = 'host/go_frequency_v46_r2_check.py'
TEST = 'tests/test_go_frequency_v46_r2.py'
TEST_SHA = 'f914bcd2cf6360eecf3af98ddca484cb135c1eb6cf94dd1c24c0089020873e58'
TEST_BYTES = 13226
HELPER = 'tests/test_go_bootstrap_native_v34_r4.py'
HELPER_SHA = '3574ad5f729162ef6a26e8f4f133210bcec6bcc8e2f74c99d1355b67974cd8ef'
HELPER_BYTES = 32468
FUNCTIONS = ('fixed', 'tripwires', 'load_model', 'failure_code', 'failure_frames', 'diagnostic')
METHOD = 'GoFrequencyV46R2Tests.test_four_first_baseline_refusals_keep_zero_radio_mutations_and_known_inventory_closed'
MODEL = 'tests/go_bootstrap_host_model_v34_r3.py'
MODEL_SHA = 'd8c07c9aa2e5e7c7c009f9411d7cb6ad3f820b12273639aad96526738dc6358f'
MODEL_BYTES = 25155
PLAN = 'host/go_frequency_v46_source_manifest.json'
PLAN_SHA = '090392942b3472e45b1eb5f3ccf8b06a236b273255ce510fe52efc0fd20bcc7e'
PLAN_BYTES = 3950
CHILD_SECONDS = 120
EXPECTED_INPUTS = 26
ORIGINAL_FIRST_RESULT = 'results/go-frequency-v46-host-model-20261002-160557-b9335060'
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
    raw_helper = add(inputs, HELPER, fixed(HELPER, HELPER_SHA, HELPER_BYTES))
    helper_tree = ast.parse(raw_helper.decode('utf-8'))
    selected = tuple(node.name for node in helper_tree.body
        if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS)
    if selected != FUNCTIONS: raise ValueError('helper_definition_inventory_changed')
    plan = json.loads(add(inputs, PLAN, fixed(PLAN, PLAN_SHA, PLAN_BYTES)))
    if type(plan) is not dict or set(plan) != {'schema', 'sources'} or plan['schema'] != 'go-frequency-v46-host':
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
    wanted = {'PLAN', 'PLAN_SHA', 'PLAN_BYTES', 'MODEL', 'MODEL_SHA', 'MODEL_BYTES',
        'HELPER', 'HELPER_SHA', 'HELPER_BYTES', 'FUNCTIONS', 'STOCK', 'WPA'}
    constants = {target.id: ast.literal_eval(n.value) for n in parsed.body if isinstance(n, ast.Assign)
        for target in n.targets if isinstance(target, ast.Name) and target.id in wanted}
    expected = dict(PLAN=PLAN, PLAN_SHA=PLAN_SHA, PLAN_BYTES=PLAN_BYTES, MODEL=MODEL,
        MODEL_SHA=MODEL_SHA, MODEL_BYTES=MODEL_BYTES, HELPER=HELPER, HELPER_SHA=HELPER_SHA,
        HELPER_BYTES=HELPER_BYTES, FUNCTIONS=FUNCTIONS, STOCK=STOCK, WPA=WPA)
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
        'One unique new fixed v46 GO17 HOST first-baseline refusal method: exactly four '
        'modeled reply cases (present GET_INTERFACE frequency conflict, missing ASSOCIATED '
        'BSS, wrong associated-BSS frequency, missing BI). The original seven-case first '
        'method remains FAIL; original result path: ' + ORIGINAL_FIRST_RESULT + '. Its '
        'completed missing38 positive, ap_no_freq and ap_wrong_freq cases are prior partial '
        'evidence only and are not replayed or promoted to seven-case PASS. This new method '
        'does not repeat positive/AP flows or the six pure event-parser negatives. '
        'The native 17-source graph, model reply helper and six old FunctionDefs are unchanged. '
        'The actual Loader/F45/Entry/neutral accounting Store/ProcReader/Budget/GO Store/'
        'Native46/Bootstrap algorithms execute only the four first-baseline refusal paths. '
        'The corrected HOST assertion checks exact tuple () for unpublished canonical history; '
        'all following original restore_failure, zero ChildOwner tickets, scan-fault hits, '
        'known native inventory closure and no modeled live FD assertions must complete. '
        'CREATE/DELETE/GROUP_ADD remain zero. No original reservation/current/reconciled '
        'journal, logical restoration or radio grant is fabricated for these early failures. '
        'The original secondary reservation_or_publication_pending remains expected; '
        'known local inventory closure is not an overall logical restoration proof. '
        'This is not a successful GO creation/same8-to9/ACK-ECHO/phase-CAS/AP-restore/event-parser/'
        'cap-expiry/foreign-grant coverage claim. No Native/grant/canonical/clock/budget is '
        'replaced. Linux paths, Proc, FD/OFD, fork/exec, netlink/Unix credentials and clock '
        'are pinned explicit OS models; no actual child branch/FD3/watchdog executes. '
        'PC source/WPA/stock archive and ZIP byte/CRC data are actual; synthetic Python/CLI '
        'identities are HOST-only and forbidden in device preparers. Device/RF/phone/'
        'physical closure/actual P011 restore and GO/IP/DHCP/TLS/send/receive service remain '
        'untested/false. The HOST cap stays 120 seconds; no native quota or active/preparation/'
        'cleanup cap is increased/renewed and no unknown state is cleared. Only six pinned '
        'old FunctionDefs are selected, never an old TestCase/checker/START method. '
        '26 immutable private inputs and original raw streams are retained once. Only the '
        'strict four-case zero-mutation numeric marker plus Ran1/OK, child0 and no timeout '
        'publish four ZIP members. Failure publishes only result/README with raw private; '
        'no automatic retry.\n').encode('ascii')
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
    output = BASE / 'results' / ('go-frequency-v46-r2-baseline-refusals-' +
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
    marker = re.fullmatch(rb'GO_FREQUENCY_V46_R2_BASELINE_REFUSALS_PASS cases=4 creates=(0) group_adds=(0) closed_cases=(4) scan_requests=(3)\r?\n', stdout)
    model_counts = tuple(int(value) for value in marker.groups()) if marker is not None else None
    stdout_reviewed = model_counts == (0, 0, 4, 3)
    stderr_reviewed = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = complete and invoked and code == 0 and not timeout and stdout_reviewed and stderr_reviewed
    value = dict(schema='go-frequency-v46-r2-baseline-refusals-host', selected_method=METHOD, selected_method_count=1,
        new_method_invocations=int(invoked), old_test_method_invocations=0, old_wrapper_invocations=0,
        source_count=len(rows), sources=rows, source_manifest_sha256=PLAN_SHA, source_manifest_bytes=PLAN_BYTES,
        test_sha256=TEST_SHA, test_bytes=TEST_BYTES, model_sha256=MODEL_SHA, model_bytes=MODEL_BYTES,
        helper_sha256=HELPER_SHA, helper_bytes=HELPER_BYTES, helper_function_names=FUNCTIONS,
        helper_definition_inventory_source_verified=source_verified,
        helper_functions_only_loaded=passed, old_test_class_or_method_loaded=False,
        checker_sha256=hashlib.sha256(own).hexdigest(), source_integrity_verified=source_verified,
        python35_syntax_verified=source_verified, verification_error=verification_error,
        snapshot_error=snapshot_error, launch_error=launch_error, host_method_passed=passed,
        host_exit=code, timeout=timeout, host_child_timeout_seconds=CHILD_SECONDS, host_elapsed_seconds=elapsed,
        input_snapshot_complete=complete, input_snapshot_entry_count=len(input_rows), expected_input_snapshot_entry_count=EXPECTED_INPUTS,
        inputs=input_rows, child_reads_private_snapshot=invoked, child_python_isolated_mode=True,
        original_seven_case_first_method_passed=False,
        original_first_method_result_path=ORIGINAL_FIRST_RESULT,
        original_completed_partial_case_names=('missing38_positive', 'ap_no_freq', 'ap_wrong_freq'),
        original_partial_case_evidence_reevaluated_or_promoted=False,
        original_failure_raw_or_source_modified=False,
        native_go17_first_baseline_refusal_boundary_host_model_tested=passed,
        native_original_loader_entry_algorithm_host_model_tested=passed,
        native_no_store_publication_and_no_child_launch_host_model_tested=passed,
        native_go_creation_same8_to9_and_phase_cas_tested=False,
        native_ack_echo_creator_or_successful_group_tested=False,
        declared_fresh_model_case_count=4, declared_event_parser_no_io_negative_count=0,
        four_first_baseline_no_create_group_add_refusals_model_tested=passed,
        four_original_post_history_restore_failure_and_local_closure_checks_model_tested=passed,
        positive_missing38_flow_replayed=False, two_ap_restore_flows_replayed=False,
        six_original_event_parser_negatives_replayed=False,
        seven_case_aggregate_pass_claimed=False,
        old_eleven_case_method_or_full_cap_deny_matrix_replayed=False,
        baseline_model_create_count=None if model_counts is None else model_counts[0],
        baseline_model_group_add_count=None if model_counts is None else model_counts[1],
        baseline_model_closed_case_count=None if model_counts is None else model_counts[2],
        baseline_model_get_scan_request_count=None if model_counts is None else model_counts[3],
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


