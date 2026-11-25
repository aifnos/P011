"""One new fixed v59 bounded-stage HOST method; ROOT execution only.

Twenty-eight fixed private inputs retain GO58 plus the parent Bootstrap bytes
for SOURCE AST comparison only. One isolated -I -B child runs nine fresh
constructor domains and actual _stage/Native._begin/_check pure predicates.
Only first baseline10->15 changes in run; all other Bootstrap class bodies
remain. Original until301, stage range<=20, cleanup and quotas stay bounded.
No baseline snapshot, run, reserve, actors/pins, _record/FD factory, child,
RF, restore, performance or phone test runs. Derived scope+5 close caps may
numerically follow scope; this is not a claim all local cap numbers stayed.
Only six old FunctionDefs are loaded, not old TestCase/method/checker/START.
Physical P011/Linux/Proc/OFD/closure remains untested; raw numeric HOST marker
and actual fixed PC source/stock/WPA bytes and ZIP CRC are separately checked.
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
CHECKER = 'host/go_baseline_bound_v59_check.py'
TEST = 'tests/test_go_baseline_bound_v59.py'
TEST_SHA = 'a634761d1d5a433007f460eeff2e1ee32f0df3699528d593385a30dc3d0431fc'
TEST_BYTES = 15839
HELPER = 'tests/test_go_bootstrap_native_v34_r4.py'
HELPER_SHA = '3574ad5f729162ef6a26e8f4f133210bcec6bcc8e2f74c99d1355b67974cd8ef'
HELPER_BYTES = 32468
FUNCTIONS = ('fixed', 'tripwires', 'load_model', 'failure_code', 'failure_frames', 'diagnostic')
METHOD = 'GoBaselineBoundV59Tests.test_stage15_original_until_clamp_refusals_and_clock_without_radio'
MODEL = 'tests/go_bootstrap_host_model_v34_r3.py'
MODEL_SHA = 'd8c07c9aa2e5e7c7c009f9411d7cb6ad3f820b12273639aad96526738dc6358f'
MODEL_BYTES = 25155
PLAN = 'host/go_baseline_budget_v58_source_manifest.json'
PLAN_SHA = '0c987d6e667a0d4adce867b121493436f9bf2ba11380acc97e11efbf320a30a0'
PLAN_BYTES = 3957
PARENT_PLAN = 'host/go_owner_coalesce_v56_r2_source_manifest.json'
PARENT_PLAN_SHA = 'a7d6e6704b04cd606b3a1da7c48ca7b5fe86eb118a934686cb96fd6beba862bf'
PARENT_PLAN_BYTES = 3954
DELTA_MODULES = ('mta_go_bootstrap',)
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


def stage_source_bounds(old_raw, new_raw):
    """SOURCE only: first run baseline10 becomes15, remaining class unchanged."""
    classes, calls = [], []
    for raw in (old_raw, new_raw):
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        found = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'GoBootstrap']
        if len(found) != 1: raise ValueError('bootstrap_class_changed')
        cls = found[0]; classes.append(cls)
        runs = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'run']
        if len(runs) != 1: raise ValueError('bootstrap_run_changed')
        rows = sorted((n for n in ast.walk(runs[0]) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
            and n.func.value.id == 'self' and n.func.attr == '_stage'),
            key=lambda n: (n.lineno, n.col_offset))
        if any(len(n.args) != 1 or n.keywords for n in rows): raise ValueError('stage_shape_changed')
        calls.append(rows)
    if ([ast.literal_eval(n.args[0]) for n in calls[0]] != [10, 5, 10, 20, 20] or
            [ast.literal_eval(n.args[0]) for n in calls[1]] != [15, 5, 10, 20, 20]):
        raise ValueError('stage_constants_changed')
    calls[0][0].args[0] = ast.Constant(value=15)
    if ast.dump(classes[0], include_attributes=False) != ast.dump(classes[1], include_attributes=False):
        raise ValueError('other_bootstrap_class_body_changed')


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
            ('v58_loaded', PLAN, PLAN_SHA, PLAN_BYTES)):
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
    graph, current_bootstrap = None, None
    for row in current_rows:
        raw = add(inputs, row['path'], fixed(row['path'], row['sha256'], row['bytes']))
        parsed = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if any(isinstance(n, ast.Assert) for n in ast.walk(parsed)): raise ValueError('target_assert_changed')
        if row['module'] == 'mta_go_deployment':
            graph = [ast.literal_eval(n.value) for n in parsed.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'MODULES' for t in n.targets)]
        if row['module'] == 'mta_go_bootstrap': current_bootstrap = raw
    if graph != [MODULES]: raise ValueError('loader_graph_changed')
    original = next(row for row in parent_rows if row['module'] == 'mta_go_bootstrap')
    original_raw = add(inputs, original['path'], fixed(original['path'], original['sha256'], original['bytes']))
    stage_source_bounds(original_raw, current_bootstrap)
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
        'One new v59 bounded-stage HOST method uses actual GO58 Loader/F Entry/'
        'neutral CLIENT accounting/GO Bootstrap Store/Native constructors under '
        'the original explicit syscall/FD/Proc/clock models. Nine fresh cases '
        'call actual _stage and Native._begin/_check, without Bootstrap.run, '
        'baseline snapshot, actors/pins, Store.reserve, _record/FD factory, fork, '
        'RF, GROUP_ADD, canonical publication or restore. Four stages issue '
        '(16,301,16,16); seven refusals cover original-until expiry, caller stop, '
        'invalid0/21/bool, issued-stage expiry and clock regression. Normal clock1 '
        'issues16 and clock299 clamps to original301, not314. The accounting '
        'slice initially remains actual Entry clock1+3=4, not11, and refusal '
        'never renews its previous issued period. Original until301, stage range '
        '<=20, quotas and cleanup stay unchanged. SOURCE AST compares the whole '
        'GoBootstrap class and permits only first run baseline10->15; other run '
        'stages5/10/20/20 and all other class bodies remain. This is not evidence '
        'that real baseline or Store.reserve can finish. Existing scope+5 local '
        'FD close caps numerically follow a changed scope; no claim is made that '
        'all derived local numbers are unchanged. No _record call is made to '
        'replay its already-unchanged ticket algorithm or manufacture closure. '
        'Only current GO58 graph algorithms load. Parent map and old Bootstrap '
        'bytes are SOURCE-only lineage, never another old graph/method execution. '
        'Only six fixed helper FunctionDefs load, never old TestCase/checker/'
        'START. Physical Linux/Proc/OFD/child/once-close/EBADF/platform, P011 '
        'performance, actual baseline completion, complete Native restore, '
        'phone/IP/DHCP/TLS/send/receive all remain untested/false. Archived PC '
        'WPA/stock-three/source bytes and public ZIP bytes/CRC are actual. '
        'Twenty-eight immutable private inputs, one -I -B child, HOST120, no '
        'retry and raw streams are retained. Success requires fixed numeric '
        '9/4/7/16/301/301 marker plus Ran1/OK, exit0 and no timeout, then publishes '
        'four members; failure publishes result/README only with raw private. '
        'No credentials, private key, raw Native inventory or user identifiers '
        'are published. This method does not upgrade any prior full/device '
        'failure or combine earlier component results into a full PASS.\n').encode('ascii')
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
    output = BASE / 'results' / ('go-baseline-bound-v59-host-model-' +
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
        rb'GO_BASELINE_BOUND_V59_HOST_PASS cases=(9) issuances=(4) refused=(7) '
        rb'normal_end=(16) clamped_end=(301) original_until=(301) rf_calls=0\r?\n', stdout)
    model_counts = tuple(int(value) for value in marker.groups()) if marker is not None else None
    stdout_reviewed = model_counts == (9, 4, 7, 16, 301, 301)
    stderr_reviewed = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = complete and invoked and code == 0 and not timeout and stdout_reviewed and stderr_reviewed
    value = dict(schema='go-baseline-bound-v59-host', selected_method=METHOD, selected_method_count=1,
        new_method_invocations=int(invoked), old_test_method_invocations=0, old_wrapper_invocations=0,
        source_manifest_count=len(graphs), loaded_source_graph_count=1 if invoked else 0,
        modules_per_loaded_graph=17, source_graphs=graphs,
        source_count=len({row['path'] for graph in graphs for row in graph['sources']}),
        loaded_source_count=17 if invoked else 0, parent_bootstrap_source_only_count=1,
        exact_lineage_delta_module_names=DELTA_MODULES,
        test_sha256=TEST_SHA, test_bytes=TEST_BYTES, model_sha256=MODEL_SHA, model_bytes=MODEL_BYTES,
        helper_sha256=HELPER_SHA, helper_bytes=HELPER_BYTES, helper_function_names=FUNCTIONS,
        helper_definition_inventory_source_verified=source_verified,
        helper_functions_only_loaded=passed, old_test_class_or_method_loaded=False,
        parent_source_graph_or_old_bootstrap_algorithm_executed=False,
        checker_sha256=hashlib.sha256(own).hexdigest(), source_integrity_verified=source_verified,
        python35_syntax_verified=source_verified, verification_error=verification_error,
        snapshot_error=snapshot_error, launch_error=launch_error, host_method_passed=passed,
        host_exit=code, timeout=timeout, host_child_timeout_seconds=CHILD_SECONDS, host_elapsed_seconds=elapsed,
        input_snapshot_complete=complete, input_snapshot_entry_count=len(input_rows), expected_input_snapshot_entry_count=EXPECTED_INPUTS,
        inputs=input_rows, child_reads_private_snapshot=invoked, child_python_isolated_mode=True,
        original_failed_source_or_raw_modified=False, old_actors_pins_frequency_or_full_flow_replayed=False,
        native_go17_bounded_stage_predicates_host_model_tested=passed,
        native_original_loader_entry_constructor_algorithm_host_model_tested=passed,
        native_original_stage_cap_calculation_stubbed=False,
        stage_normal_or_clamp_result_injected=False, native_positive_grant_or_canonical_stubbed=False,
        native_bootstrap_run_tested=False, native_baseline_snapshot_completed=False,
        native_go_store_reservation_or_publication_tested=False,
        native_go_creation_same8_to9_and_phase_cas_tested=False,
        native_ack_echo_creator_or_successful_group_tested=False,
        declared_fresh_model_case_count=9, declared_issued_stage_count=4, declared_refusal_case_count=7,
        case_names=('normal15', 'clamp_original', 'expired_original', 'caller_stop',
            'invalid_zero', 'invalid_twentyone', 'invalid_bool', 'issued_stage_expired', 'clock_regressed'),
        source_first_baseline_stage_seconds_before=10, source_first_baseline_stage_seconds_after=15,
        source_other_run_stage_seconds=(5, 10, 20, 20),
        source_other_bootstrap_class_bodies_unchanged_verified=source_verified,
        source_initial_baseline_stage_allocation_changed=True, original_session_until_model_expected=301.0,
        original_entry_slice_deadline_model_expected=4.0,
        derived_scope_plus5_local_close_cap_numbers_may_follow_scope=True,
        all_local_cap_numeric_values_unchanged_claimed=False,
        record_or_fd_factory_exercised=False, baseline_wall_performance_proven=False,
        model_case_count=None if model_counts is None else model_counts[0],
        modeled_issued_stage_count=None if model_counts is None else model_counts[1],
        modeled_refusal_case_count=None if model_counts is None else model_counts[2],
        modeled_normal_stage_end=None if model_counts is None else model_counts[3],
        modeled_clamped_stage_end=None if model_counts is None else model_counts[4],
        modeled_original_until=None if model_counts is None else model_counts[5],
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
