"""One unique new GO63 affected HOST model method; ROOT execution only.

Twenty-eight private fixed inputs: current GO62 graph and parent60 Native
SOURCE normalization only. Twelve isolated algorithm domains run under the
original explicit Linux/FD/Proc/netlink/Unix/clock models. The new normal full
run remains unwrapped; real retained Snapshot objects plus original-forward
OS validation marks count21, not a readiness flag. Four changed callsites
have actual modeled bytes that contradict their originals. Initial and
cleanup double samples, terminal postcheck and unknown close stay strict.
No prior TestCase/method/checker or old full model flow is executed.
One -I -B child, HOST120, no retry, original quotas/periods, success4/failure2
public ZIPs. Model RF algorithm coverage is not physical RF/P011/phone proof.
"""
import ast
import datetime
import copy
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
CHECKER = 'host/go_fresh_boundary_v63_check.py'
TEST = 'tests/test_go_fresh_boundary_v63.py'
TEST_SHA = '55942f4df08af88d8ccb019b130cf909ec97c490c7f615b4f123c8ba3c51f0c5'
TEST_BYTES = 38095
HELPER = 'tests/test_go_bootstrap_native_v34_r4.py'
HELPER_SHA = '3574ad5f729162ef6a26e8f4f133210bcec6bcc8e2f74c99d1355b67974cd8ef'
HELPER_BYTES = 32468
FUNCTIONS = ('fixed', 'tripwires', 'load_model', 'failure_code', 'failure_frames', 'diagnostic')
METHOD = 'GoFreshBoundaryV63Tests.test_actual_single_fresh_boundaries_and_retained_double_restore_gates'
MODEL = 'tests/go_bootstrap_host_model_v34_r3.py'
MODEL_SHA = 'd8c07c9aa2e5e7c7c009f9411d7cb6ad3f820b12273639aad96526738dc6358f'
MODEL_BYTES = 25155
PLAN = 'host/go_fresh_boundary_v62_source_manifest.json'
PLAN_SHA = 'b959ae92e6ef048b3724e716e09503a7607f0b07e6eef5f4e14be71bd545e842'
PLAN_BYTES = 3955
PARENT_PLAN = 'host/go_proc_diagnostic_v60_source_manifest.json'
PARENT_PLAN_SHA = 'c2be8155c68594d2baa863c5ff6a99b38f6e231c32eb79bb2f94aeac77a210cf'
PARENT_PLAN_BYTES = 3956
DELTA_MODULES = ('mta_go_native',)
CHILD_SECONDS = 120
EXPECTED_INPUTS = 28
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


def fresh_source_bounds(old_raw, new_raw):
    """Only helper addition/four middle substitutions; no old algorithm runs."""
    trees = [ast.parse(raw) for raw in (old_raw, new_raw)]
    for tree in trees:
        if not tree.body or not isinstance(tree.body[0], ast.Expr) or not isinstance(tree.body[0].value, ast.Constant):
            raise ValueError('HOST documentation shape')
        tree.body.pop(0)
    classes = [[n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'NativeGoResources'] for tree in trees]
    if any(len(rows) != 1 for rows in classes): raise ValueError('HOST native class changed')
    added = [n for n in classes[1][0].body if isinstance(n, ast.FunctionDef) and n.name == '_fresh_boundary_snapshot_v62']
    exact = ast.parse('def _fresh_boundary_snapshot_v62(self):\n'
        '    if self._scope_cleanup is not False: return self._stable_snapshot()\n'
        '    value=self._snapshot_once()\n'
        '    self.observations.append(value)\n'
        '    self._check(); return value\n').body[0]
    if len(added) != 1 or ast.dump(added[0], include_attributes=False) != ast.dump(exact, include_attributes=False):
        raise ValueError('HOST exact fresh helper changed')
    classes[1][0].body.remove(added[0])
    for name in ('baseline_current', 'interface_current', 'origin_current', '_group_status'):
        methods = [n for n in classes[1][0].body if isinstance(n, ast.FunctionDef) and n.name == name]
        calls = [n for n in ast.walk(methods[0]) if isinstance(n, ast.Call) and
            isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and
            n.func.value.id == 'self' and n.func.attr == '_fresh_boundary_snapshot_v62'] if len(methods) == 1 else []
        if len(calls) != 1 or calls[0].args or calls[0].keywords:
            raise ValueError('HOST exact middle callsite changed')
        calls[0].func.attr = '_stable_snapshot'
    if ast.dump(trees[0], include_attributes=False) != ast.dump(trees[1], include_attributes=False):
        raise ValueError('HOST other Native algorithms changed')


def verify(inputs):
    """SOURCE AST/hash only; no production/old tests are imported here."""
    raw_test = add(inputs, TEST, fixed(TEST, TEST_SHA, TEST_BYTES))
    raw_model = add(inputs, MODEL, fixed(MODEL, MODEL_SHA, MODEL_BYTES))
    raw_helper = add(inputs, HELPER, fixed(HELPER, HELPER_SHA, HELPER_BYTES))
    helper_tree = ast.parse(raw_helper.decode('utf-8'))
    selected = tuple(node.name for node in helper_tree.body
        if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS)
    if selected != FUNCTIONS: raise ValueError('helper_definition_inventory_changed')
    graphs = []
    for label, path, sha, size in (
            ('parent_source_only', PARENT_PLAN, PARENT_PLAN_SHA, PARENT_PLAN_BYTES),
            ('v62_loaded', PLAN, PLAN_SHA, PLAN_BYTES)):
        plan = json.loads(add(inputs, path, fixed(path, sha, size)))
        if type(plan) is not dict or set(plan) != {'schema', 'sources'} or plan['schema'] != 'go-frequency-v46-host':
            raise ValueError('graph_changed')
        rows = plan['sources']
        if (type(rows) is not list or len(rows) != 17 or tuple(r['module'] for r in rows) != MODULES
                or any(set(r) != {'module', 'path', 'sha256', 'bytes'} for r in rows)):
            raise ValueError('graph_changed')
        graphs.append(dict(label=label, source_manifest_path=path,
            source_manifest_sha256=sha, source_manifest_bytes=size, sources=rows))
    parent_rows, current_rows = graphs[0]['sources'], graphs[1]['sources']
    changes = tuple(current['module'] for before, current in zip(parent_rows, current_rows) if before != current)
    if changes != DELTA_MODULES: raise ValueError('graph_lineage_changed')
    graph, current_source = None, {}
    for row in current_rows:
        raw = add(inputs, row['path'], fixed(row['path'], row['sha256'], row['bytes']))
        parsed = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if any(isinstance(n, ast.Assert) for n in ast.walk(parsed)): raise ValueError('target_assert_changed')
        if row['module'] == 'mta_go_deployment':
            graph = [ast.literal_eval(n.value) for n in parsed.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'MODULES' for t in n.targets)]
        current_source[row['module']] = raw
    if graph != [MODULES]: raise ValueError('loader_graph_changed')
    original_source = {}
    for original in parent_rows:
        if original['module'] in DELTA_MODULES:
            original_source[original['module']] = add(inputs, original['path'],
                fixed(original['path'], original['sha256'], original['bytes']))
    fresh_source_bounds(original_source['mta_go_native'], current_source['mta_go_native'])
    distinct_sources = {row['path'] for item in graphs for row in item['sources']}
    if len(distinct_sources) != 18: raise ValueError('graph_union_changed')
    for path, relative, sha, size in STOCK: add(inputs, relative, fixed(relative, sha, size))
    add(inputs, WPA[0], fixed(*WPA))
    parsed = ast.parse(raw_test.decode('utf-8'))
    names = [cls.name + '.' + method.name for cls in parsed.body if isinstance(cls, ast.ClassDef)
        for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')]
    if names != [METHOD]: raise ValueError('method_changed')
    wanted = {'PLAN', 'PLAN_SHA', 'PLAN_BYTES', 'PARENT_PLAN', 'PARENT_PLAN_SHA',
        'PARENT_PLAN_BYTES', 'MODEL', 'MODEL_SHA', 'MODEL_BYTES',
        'HELPER', 'HELPER_SHA', 'HELPER_BYTES', 'FUNCTIONS', 'STOCK', 'WPA'}
    constants = {target.id: ast.literal_eval(n.value) for n in parsed.body if isinstance(n, ast.Assign)
        for target in n.targets if isinstance(target, ast.Name) and target.id in wanted}
    expected = dict(PLAN=PLAN, PLAN_SHA=PLAN_SHA, PLAN_BYTES=PLAN_BYTES,
        PARENT_PLAN=PARENT_PLAN, PARENT_PLAN_SHA=PARENT_PLAN_SHA, PARENT_PLAN_BYTES=PARENT_PLAN_BYTES,
        MODEL=MODEL, MODEL_SHA=MODEL_SHA, MODEL_BYTES=MODEL_BYTES, HELPER=HELPER,
        HELPER_SHA=HELPER_SHA, HELPER_BYTES=HELPER_BYTES, FUNCTIONS=FUNCTIONS, STOCK=STOCK, WPA=WPA)
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
        'One new GO63 affected HOST method loads actual fixed GO62 Loader/F '
        'Entry/neutral accounting Store/bound ProcReader/GO Store/Native/'
        'ProcessOwner/Bootstrap definitions. All Linux files, FD metadata, '
        'Proc, netlink multipart ACK/ECHO, Unix replies/credentials, parent '
        'fork branch and clock are explicit HOST syscall models. Original '
        'canonical/grant/typed observation producers and success results '
        'are never replaced. No Native method is patched or counted by a '
        'wrapper. Original-forward modeled OS validate events are filtered '
        'to the actual snapshot caller and checked against exact actual '
        'core.Snapshot objects retained by Native. The unwrapped normal '
        'new full algorithm run must retain21 snapshots: initial2 plus '
        'eleven active-middle fresh snapshots plus cleanup8. Original '
        'wait_group keeps two actual AP STATUS exchanges and confirm keeps '
        'one, hence AP3. Original creator ACK plus ECHO/same ticket/owned8, '
        'GO9 event/status/kernel, DEL, 13 native journal canonical versions/'
        'generation12 and all modeled inventory close facts must remain. '
        'This is model coverage, not physical RF or a P011 baseline timing '
        'result. Four affected callsites are rejected by actual modeled '
        'data: current stock digest/routes, an extra interface before '
        'CREATE, changed owned identity after ACK/ECHO, and GO9 kernel '
        'frequency contrary to actual event/AP STATUS. Initial second and '
        'restore second route samples still refuse instability. Unknown '
        'modeled close physically removes a model FD then raises its same '
        'EIO: Native retains attempted/closedFalse/original error, cannot '
        'retry and cannot claim restoration. Local endpoint and physical '
        'closure semantics are still OS models. Terminal deadline/cancel '
        'are two constructor-only helper domains. An explicit HOST clock/'
        'frame hook returns the first actual snapshot diagnostic-tail '
        'clock value and then sets the original stage cutoff or caller '
        'stop, before original fresh append/_check. The retained Snapshot/'
        'IO completion and unchanged16/301 periods must be checked; this '
        'does not issue a baseline/current/grant. Actual completed cleanup '
        'then uses the new helper with original cleanupTrue and observes '
        'two original samples. A separate constructor unknownNone scope '
        'is deny-only fixture data, not a cleanup source or authority, and '
        'must also take the old double-sample fallback. This component '
        'does not claim every event/type/STATUS mutation variant or '
        'equivalence of removing the second middle temporal sample. '
        'Twelve isolated model domains/ten refusals/six new full model '
        'runs/two fallback pairs execute only this unique method. Parent '
        'GO60 Native bytes are SOURCE-only: normalization confirms only '
        'one helper addition and four middle callsite changes; startup '
        'and all restoration double methods, every other algorithm, '
        'quota and original period stay intact. Twenty-eight immutable '
        'private input copies; six old helper FunctionDefs only, never '
        'old TestCase/method/checker. One -I -B child, HOST120, no retry. '
        'Success requires fixed numeric12/10/6/21/2/11/8/3/13/2 marker, '
        'Ran1/OK, exit0 and no timeout. Only then numeric reviewed raw '
        'joins result/README in four ZIP members. Failure raw remains '
        'private and public ZIP has two members. Private modeled event/'
        'SSID/credential bytes, traceback and raw Native data never '
        'enter public JSON/ZIP. Actual archived PC stock3/WPA/source and '
        'ZIP CRC/bytes are checked. Linux/ARM Python/CLI identities are '
        'models. Actual child branch/FD3/watchdog/OFD, RF/performance/'
        'device/phone/IP/DHCP/TLS/send/receive/whole Native restore and '
        'production availability remain false; no prior device failure '
        'is upgraded or old component results combined into a PASS.\n').encode('ascii')
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
        print('PC_ONLY fixed GO17 HOST component; no device/network/path arguments')
        return 2
    output = BASE / 'results' / ('go-fresh-boundary-v63-host-model-' +
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
        rb'GO_FRESH_BOUNDARY_V63_HOST_PASS domains=(12) refusals=(10) full_runs=(6) '
        rb'snapshots=(21) initial=(2) active=(11) restore=(8) ap_status=(3) journal=(13) '
        rb'fallback_pairs=(2) rf_physical=0\r?\n', stdout)
    counts = tuple(int(value) for value in marker.groups()) if marker is not None else None
    stdout_reviewed = counts == (12, 10, 6, 21, 2, 11, 8, 3, 13, 2)
    stderr_reviewed = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = complete and invoked and code == 0 and not timeout and stdout_reviewed and stderr_reviewed
    value = dict(schema='go-fresh-boundary-v63-host', selected_method=METHOD, selected_method_count=1,
        new_method_invocations=int(invoked), old_test_method_invocations=0, old_wrapper_invocations=0,
        source_manifest_count=len(graphs), loaded_source_graph_count=12 if passed else None,
        declared_model_domain_count=12, modules_per_loaded_graph=17, source_graphs=graphs,
        source_count=len({row['path'] for graph in graphs for row in graph['sources']}),
        loaded_distinct_source_count=17 if invoked else 0, parent_native_source_only_count=1,
        exact_lineage_delta_module_names=DELTA_MODULES,
        test_sha256=TEST_SHA, test_bytes=TEST_BYTES, model_sha256=MODEL_SHA, model_bytes=MODEL_BYTES,
        helper_sha256=HELPER_SHA, helper_bytes=HELPER_BYTES, helper_function_names=FUNCTIONS,
        helper_definition_inventory_source_verified=source_verified,
        helper_functions_only_loaded=passed, old_test_class_or_method_loaded=False,
        parent_source_graph_or_old_native_algorithm_executed=False,
        source_exact_added_helper_and_four_middle_substitutions_verified=source_verified,
        source_initial_and_all_restore_double_samples_unchanged_verified=source_verified,
        source_other_native_algorithm_bodies_unchanged_verified=source_verified,
        checker_sha256=hashlib.sha256(own).hexdigest(), source_integrity_verified=source_verified,
        python35_syntax_verified=source_verified, verification_error=verification_error,
        snapshot_error=snapshot_error, launch_error=launch_error, host_method_passed=passed,
        host_exit=code, timeout=timeout, host_child_timeout_seconds=CHILD_SECONDS, host_elapsed_seconds=elapsed,
        input_snapshot_complete=complete, input_snapshot_entry_count=len(input_rows), expected_input_snapshot_entry_count=EXPECTED_INPUTS,
        inputs=input_rows, child_reads_private_snapshot=invoked, child_python_isolated_mode=True,
        original_failed_source_or_raw_modified=False, prior57_59_61_or_old_full_methods_replayed=False,
        native_original_loader_entry_store_native_bootstrap_host_model_tested=passed,
        actual_native_function_wrapped_or_replaced=False,
        modeled_validate_counter_forwards_original_and_requires_actual_snapshot_caller=True,
        modeled_counter_used_as_success_or_permission=False,
        actual_core_snapshot_or_canonical_or_grant_or_success_result_injected=False,
        native_new_normal_unwrapped_full_algorithm_host_model_tested=passed,
        normal_actual_retained_snapshots21_initial2_active11_restore8_host_model_tested=passed,
        wait_group_double_actual_status_and_durable_confirm_status_host_model_tested=passed,
        create_original_ack_echo_ticket_owned8_to_group9_host_model_tested=passed,
        delete_original_and_13_canonical_generation12_host_model_tested=passed,
        modeled_normal_complete_closed_inventory_and_baseline_key_restore_host_model_tested=passed,
        all_domains_claimed_pending_false=False,
        baseline_current_stock_and_route_change_refusals_host_model_tested=passed,
        interface_current_extra_netdev_before_create_refusal_host_model_tested=passed,
        origin_current_actual_creator_identity_change_refusal_host_model_tested=passed,
        group_actual_event_status_vs_kernel_frequency_refusal_host_model_tested=passed,
        initial_and_cleanup_second_sample_change_refusals_host_model_tested=passed,
        terminal_first_snapshot_append_then_deadline_cancel_refusals_host_model_tested=passed,
        terminal_clock_frame_hook_declared=True, terminal_scope_claimed_baseline_grant=False,
        uncertain_close_original_error_no_retry_pending_host_model_tested=passed,
        exact_cleanup_true_and_unknown_none_double_fallback_host_model_tested=passed,
        unknown_scope_declared_deny_only_not_cleanup_authority=True,
        declared_new_full_run_count=6, declared_refusal_count=10, declared_fallback_pair_count=2,
        declared_normal_snapshot_count=21, declared_initial_double_snapshot_count=2,
        declared_active_fresh_snapshot_count=11, declared_cleanup_double_snapshot_count=8,
        declared_normal_private_ap_status_count=3, declared_normal_journal_version_count=13,
        observed_counts=counts,
        case_names=('normal', 'baseline_stock', 'baseline_routes', 'interface_extra',
            'origin_identity', 'group_kernel', 'initial_second', 'restore_second',
            'close_unknown', 'terminal_deadline', 'terminal_cancel', 'unknown_scope'),
        every_event_type_or_status_mutation_variant_tested=False,
        single_middle_sample_claimed_equivalent_to_removed_temporal_sample=False,
        original_session_until_model_expected=301.0, original_entry_slice_deadline_model_expected=4.0,
        terminal_native_stage_scope_model_expected=16.0,
        actual_p011_active75_or_baseline15_deadline_measured=False,
        modeled_rf_syscall_requests_in_new_algorithm_tested=passed, actual_rf_requested=False,
        neutral_accounting_store_native_ctor=True, linux_io_proc_netlink_unix_clock_modeled=True,
        python_cli_executable_identities_modeled=True,
        actual_pc_pinned_wpa_and_stock3_byte_inputs=True, actual_pc_zip_bytes_crc_checked=True,
        real_device_python_cli_identity_tested=False, actual_wpa_or_python_exec_tested=False,
        actual_linux_proc_or_socket_tested=False, actual_native_fork_exec_signal_wait_tested=False,
        actual_physical_fd_or_endpoint_closure_tested=False, actual_linux_platform_pass=False,
        actual_child_branch_fd3_watchdog_loop_exercised=False,
        child_inherited_ofd_and_physical_lock_behavior_tested=False,
        notify_eof_or_R_actual_child_observed=False,
        original_quota_expanded=False, original_active_cap_renewed=False, unknown_resource_cleared=False,
        model_only_python_cli_pins_forbidden_in_device_preparer=True,
        state_production_receive_gate_enabled=False, p011_go_service_available=False,
        p011_ip_dhcp_tls_send_receive_available=False, actual_p011_restore_verified=False,
        whole_native_go_or_restore_pass_claimed=False, device_accessed=False, rf_requested=False, phone_tested=False,
        private_key_or_user_id_public=False, raw_native_bytes_or_traceback_in_public_zip=False,
        full_syscall_wall_bound_verified=False, full_heap_bound_verified=False,
        stdout_fixed_marker_reviewed=stdout_reviewed, unittest_stderr_reviewed=stderr_reviewed,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        public_raw_included=passed, public_zip_member_count=4 if passed else 2)
    archive = publish(output, value, stdout, stderr, passed)
    print(json.dumps(dict(passed=passed, host_exit=code, timeout=timeout, elapsed_seconds=elapsed,
        result_zip=str(archive), zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())))
    return 0 if passed else 2 if verification_error or snapshot_error or launch_error else 1


if __name__ == '__main__': sys.exit(main())

