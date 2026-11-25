"""One fixed v57 owner-authentication causal HOST component method; ROOT only.

Thirty exact private inputs feed one -I -B child, one method, no retry.
Two isolated actual GO17 Loader/F Entry/neutral Store/Bootstrap constructors
compare GO55 with guarded GO56-r2 under pinned Linux/FD/Proc/clock syscalls.
Twenty-one fresh cases per graph (42 isolated cases, 40 refusals) transparently
forward actual Loader.authenticate calls. Normal Native auth4 becomes auth2;
standalone Entry1/Store2 and the actual post-PID Entry reauthentication remain.
Dynamic ticket/Budget/Reader/equality and Entry/Store override callbacks must
fall back to the old source chain rather than obtaining an optimized grant.
Only six old FunctionDefs load, never an old TestCase/full baseline/AP method.
PC inputs and ZIP bytes/CRC are actual; physical Linux/ARM/device/performance,
Bootstrap.run/reservation/RF/restore/IP/DHCP/phone remain untested/false.
Original native quotas/caps and HOST120 remain unchanged.
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
CHECKER = 'host/go_owner_coalesce_v57_check.py'
TEST = 'tests/test_go_owner_coalesce_v57.py'
TEST_SHA = '152ed70ef72bce9aca65e52d77b9db5017076436cf6481be8f51939e523e3e92'
TEST_BYTES = 22460
HELPER = 'tests/test_go_bootstrap_native_v34_r4.py'
HELPER_SHA = '3574ad5f729162ef6a26e8f4f133210bcec6bcc8e2f74c99d1355b67974cd8ef'
HELPER_BYTES = 32468
FUNCTIONS = ('fixed', 'tripwires', 'load_model', 'failure_code', 'failure_frames', 'diagnostic')
METHOD = 'GoOwnerCoalesceV57Tests.test_original_owner_auth_coalescence_and_fallback_refusals_without_radio'
MODEL = 'tests/go_bootstrap_host_model_v34_r3.py'
MODEL_SHA = 'd8c07c9aa2e5e7c7c009f9411d7cb6ad3f820b12273639aad96526738dc6358f'
MODEL_BYTES = 25155
PLANS = (
    ('v55', 'host/go_baseline_timing_v55_source_manifest.json',
        '32d1721de72d24a6c0f9759922a5b9dd461ee362fc22d588c3db2e7179a8ce69', 3951),
    ('v56r2', 'host/go_owner_coalesce_v56_r2_source_manifest.json',
        'a7d6e6704b04cd606b3a1da7c48ca7b5fe86eb118a934686cb96fd6beba862bf', 3954))
DELTA_MODULES = ('mta_go_executor', 'mta_go_bootstrap_store', 'mta_go_native')
CHILD_SECONDS = 120
EXPECTED_INPUTS = 30
ORIGINAL_FIRST_RESULT = 'results/go-baseline-timing-v55-20261002-181919-2ecdaadd'
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
    graphs, prior = [], None
    for label, path, sha, size in PLANS:
        plan = json.loads(add(inputs, path, fixed(path, sha, size)))
        if type(plan) is not dict or set(plan) != {'schema', 'sources'} or plan['schema'] != 'go-frequency-v46-host':
            raise ValueError('graph_changed')
        rows = plan['sources']
        if (type(rows) is not list or len(rows) != 17 or tuple(r['module'] for r in rows) != MODULES
                or any(set(r) != {'module', 'path', 'sha256', 'bytes'} for r in rows)):
            raise ValueError('graph_changed')
        if prior is not None:
            changes = tuple(current['module'] for before, current in zip(prior, rows) if before != current)
            if changes != DELTA_MODULES: raise ValueError('graph_lineage_changed')
        graph = None
        for row in rows:
            raw = add(inputs, row['path'], fixed(row['path'], row['sha256'], row['bytes']))
            parsed = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
            if any(isinstance(n, ast.Assert) for n in ast.walk(parsed)): raise ValueError('target_assert_changed')
            if row['module'] == 'mta_go_deployment':
                graph = [ast.literal_eval(n.value) for n in parsed.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == 'MODULES' for t in n.targets)]
        if graph != [MODULES]: raise ValueError('loader_graph_changed')
        graphs.append(dict(label=label, source_manifest_path=path,
            source_manifest_sha256=sha, source_manifest_bytes=size, sources=rows))
        prior = rows
    distinct_sources = {row['path'] for graph in graphs for row in graph['sources']}
    if len(distinct_sources) != 20: raise ValueError('graph_union_changed')
    for path, relative, sha, size in STOCK: add(inputs, relative, fixed(relative, sha, size))
    add(inputs, WPA[0], fixed(*WPA))
    parsed = ast.parse(raw_test.decode('utf-8'))
    names = [cls.name + '.' + method.name for cls in parsed.body if isinstance(cls, ast.ClassDef)
        for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')]
    if names != [METHOD]: raise ValueError('method_changed')
    wanted = {'PLANS', 'DELTA_MODULES', 'MODEL', 'MODEL_SHA', 'MODEL_BYTES',
        'HELPER', 'HELPER_SHA', 'HELPER_BYTES', 'FUNCTIONS', 'STOCK', 'WPA'}
    constants = {target.id: ast.literal_eval(n.value) for n in parsed.body if isinstance(n, ast.Assign)
        for target in n.targets if isinstance(target, ast.Name) and target.id in wanted}
    expected = dict(PLANS=PLANS, DELTA_MODULES=DELTA_MODULES, MODEL=MODEL,
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
    return graphs


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
        'One unique new v57 owner-authentication HOST component method compares the fixed '
        'GO55 graph with guarded GO56-r2. Twenty-one fresh isolated cases per graph give '
        '42 subcases and 40 refusals. Actual GO17 Loader authentication, F._entry, neutral '
        'CLIENT accounting Store/ProcReader/Budget and GO Bootstrap/Store/Native constructor '
        'predicates run under pinned OS/FD/Proc/clock syscall models. The transparent Loader '
        'authentication counter always forwards the actual original method and its result. '
        'Normal Native._owner calls old4/new2; standalone Entry._context remains1 and '
        'Store._owner remains2. Native._check retains the actual Bootstrap cancellation '
        'chain, giving old6/new4. Module/source failure, Native owner/rows/history, Entry '
        'reader/budget/accounting and Store owner/rows replacements still refuse. Dynamic '
        'ticket dictionaries, Budget context, Reader owns-generation, equality and both '
        'Entry/Store instance wrappers fall back to the original source checks; each '
        'callback must actually run and source poisoning must be refused. Entry wrapper '
        'forwards original B then C refuses before PID. Store wrapper forwards original '
        'C and the actual model IO PID hook poisons source, so original post-PID D refuses. '
        'The explicit synthetic PID is a deny-only fixture, not reserved Store state, a '
        'child identity, a canonical journal or authority. The non-overridden PID case '
        'also retains post-PID D. Regressed clock, original scope expiry and cancellation '
        'are refused without renewal. Original until301, stage10, all quotas, histories '
        'and failure facts are unchanged; no unknown is cleared. Every error case gets '
        'its own actual Loader/Entry/Bootstrap constructor domain, not a reused errored '
        'instance. No RF IO is performed after the pure constructor; Bootstrap.run, '
        'Store.reserve, actors/pins, canonical publication, CREATE/DELETE/GROUP_ADD, child '
        'launch and logical restoration are not run. Only six fixed original FunctionDefs '
        'are selected, never an old TestCase/method/checker/START. The original GO55 '
        'physical failed attempt is retained separately and is not promoted by this '
        'HOST comparison. Linux/Proc/FD/once-close/EBADF/fork/clock and Python/CLI identities '
        'are explicit HOST models, not physical kernel/ARM/device facts. Only PC fixed '
        'source/WPA/stock archive bytes and ZIP bytes/CRC are actual. P011 ten-second stage '
        'throughput/deadline cause, RF/GO/IP/DHCP/TLS/send/receive/phone, complete restoration '
        'and physical closure remain untested/false. Thirty private inputs, one immutable '
        'snapshot, one -I -B child and original raw streams are retained without retry. '
        'Only exact numeric marker plus Ran1/OK, exit0 and no timeout publish result/README/'
        'stdout/stderr; any failure publishes only result/README with raw private. No raw '
        'pin data, credential, private key or user ID is published. Original failed source/'
        'results are not modified; no native quota or cap is expanded.\n').encode('ascii')
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
    output = BASE / 'results' / ('go-owner-coalesce-v57-host-model-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    own = Path(__file__).read_bytes()
    inputs, graphs, source_verified = {CHECKER: own}, [], False
    verification_error = snapshot_error = launch_error = None
    try:
        graphs = verify(inputs); source_verified = True
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
    marker = re.fullmatch(
        rb'GO_OWNER_COALESCE_V57_HOST_PASS domains=2 isolated_cases=(42) refused=(40) '
        rb'native_auth55=(4) native_auth56r2=(2) entry_auth55=(1) entry_auth56r2=(1) '
        rb'store_auth55=(2) store_auth56r2=(2) check_auth55=(6) check_auth56r2=(4) rf_calls=0\r?\n', stdout)
    model_counts = tuple(int(value) for value in marker.groups()) if marker is not None else None
    stdout_reviewed = model_counts == (42, 40, 4, 2, 1, 1, 2, 2, 6, 4)
    stderr_reviewed = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = complete and invoked and code == 0 and not timeout and stdout_reviewed and stderr_reviewed
    value = dict(schema='go-owner-coalesce-v57-host', selected_method=METHOD, selected_method_count=1,
        new_method_invocations=int(invoked), old_test_method_invocations=0, old_wrapper_invocations=0,
        source_graph_count=len(graphs), modules_per_graph=17, source_graphs=graphs,
        source_count=len({row['path'] for graph in graphs for row in graph['sources']}),
        exact_lineage_delta_module_names=DELTA_MODULES,
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
        original_first_method_result_path=ORIGINAL_FIRST_RESULT,
        original_failed_source_or_raw_modified=False, old_actors_pins_frequency_or_full_flow_replayed=False,
        native_go17_owner_source_component_algorithms_host_model_tested=passed,
        native_original_loader_entry_constructor_algorithm_host_model_tested=passed,
        native_bootstrap_run_tested=False, native_go_store_reservation_or_publication_tested=False,
        native_go_creation_same8_to9_and_phase_cas_tested=False,
        native_ack_echo_creator_or_successful_group_tested=False,
        declared_paired_case_count=21, declared_fresh_model_case_count=42, declared_refusal_case_count=40,
        authenticate_counter_actual_original_method_forwarded_model_tested=passed,
        normal_auth4_to2_entry1_store2_and_check6_to4_model_tested=passed,
        dynamic_callback_fallback_and_wrapper_invocation_refusals_model_tested=passed,
        original_store_post_pid_entry_reauthentication_model_tested=passed,
        source_module_owner_rows_reader_accounting_replacements_refused_model_tested=passed,
        pre_io_clock_expiry_and_cancellation_refusals_model_tested=passed,
        loader_authentication_result_or_gate_stubbed=False,
        model_case_count=None if model_counts is None else model_counts[0],
        modeled_refusal_case_count=None if model_counts is None else model_counts[1],
        native_owner_old_auth_count=None if model_counts is None else model_counts[2],
        native_owner_new_auth_count=None if model_counts is None else model_counts[3],
        entry_old_auth_count=None if model_counts is None else model_counts[4],
        entry_new_auth_count=None if model_counts is None else model_counts[5],
        store_old_auth_count=None if model_counts is None else model_counts[6],
        store_new_auth_count=None if model_counts is None else model_counts[7],
        active_check_old_auth_count=None if model_counts is None else model_counts[8],
        active_check_new_auth_count=None if model_counts is None else model_counts[9],
        synthetic_pid_is_deny_only_not_reserved_or_grant=True,
        p011_ten_second_stage_throughput_or_deadline_cause_proven=False,
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
