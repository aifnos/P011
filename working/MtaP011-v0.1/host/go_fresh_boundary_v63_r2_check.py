"""One immutable HOST63-r2 method; only two affected refusal domains.

Original HOST63 whole method remains FAIL; its ten completed domains are
not replayed or combined into a full twelve-domain PASS. Actual original
GO62 algorithms run under the same explicit syscall/FD/Proc/clock model.
Only actual interface_current/fresh/snapshot stack introduces the extra
modeled interface. Unknown close must retain the same original EIO and
once-close/no-retry/closedFalse; private diagnostic output is best effort.
The graph, fixed six helper FunctionDefs, resource/period gates and
28-private-input/120s/single-I-B/noRetry/ZIP boundaries are unchanged.
No production, physical RF/FD3/phone or full restoration is claimed.
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
CHECKER = 'host/go_fresh_boundary_v63_r2_check.py'
TEST = 'tests/test_go_fresh_boundary_v63_r2.py'
TEST_SHA = 'b8149cf9772b056f8bc1026d05d038cee6546495ed9749f476549711873ef8dc'
TEST_BYTES = 24292
HELPER = 'tests/test_go_bootstrap_native_v34_r4.py'
HELPER_SHA = '3574ad5f729162ef6a26e8f4f133210bcec6bcc8e2f74c99d1355b67974cd8ef'
HELPER_BYTES = 32468
FUNCTIONS = ('fixed', 'tripwires', 'load_model', 'failure_code', 'failure_frames', 'diagnostic')
METHOD = 'GoFreshBoundaryV63R2Tests.test_only_interface_fresh_extra_and_uncertain_close_affected_denials'
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
        'One new immutable HOST63-r2 affected method runs only two isolated '
        'model domains: interface_extra and close_unknown. Original63 '
        'results/go-fresh-boundary-v63-host-model-20261002-212107-e8bb57ca '
        'remains whole FAIL. That original raw completed ten domains, but '
        'this wrapper neither loads/replays them nor synthesizes a twelve-'
        'domain PASS. Earlier extra-interface injection happened as soon '
        'as a ticket existed, before channel_current/caps finished. This '
        'new OS-model sendto hook forwards the original implementation and '
        'injects only if actual Native globals/self pointer and ordered '
        'snapshot/fresh/interface_current frames are present. It then '
        'adds a typed netlink interface with original request seq/port. '
        'The earlier actual channel/caps checks are not replaced or '
        'relaxed. The actual fresh Snapshot must trigger original '
        'native_baseline_changed before CREATE. Original watchdog-live '
        'durable canonical history, later original restore_intent, no '
        'CREATE/GROUP_ADD/DEL, unchanged301 period and pending marker '
        'remain checked. Known local inventories may close while the '
        'unexpected modeled network state prevents logical restoration. '
        'The close domain physically closes a model FD once, then raises '
        'the same EIO. Actual Native retains the original close error, '
        'attemptedTrue/closedFalse/known identity and closed-factsFalse. '
        'Next actual close must reject without any new model syscall or '
        'second close. The original answer1/currentNone/zero-publication/'
        'restorepending remain; missing marker is not restoration. '
        'Private FD2 diagnostic output is best effort. If bytes were '
        'emitted, original FD2/type/16KiB checks still apply, but no write '
        'is required to prove the actual refusal or resource pending. '
        'No Native method, Snapshot, canonical, grant, clock cap, budget '
        'or success result is substituted. Linux/FD/Proc/netlink/Unix '
        'and parent fork branch are explicit OS models. Only six fixed '
        'helper FunctionDefs load, never old TestCase/method/checker. '
        'Current GO62 seventeen algorithms and parent60 Native SOURCE-'
        'only normalization preserve one helper/four changed callsites '
        'and every other original source/period/quota. Twenty-eight '
        'fixed private input copies, one -I -B child, HOST120/noRetry. '
        'Success requires fixed2/2/2/1/1/0 numeric marker plus Ran1/OK, '
        'exit0/noTimeout; only then four reviewed public members include '
        'numeric raw. Failure publishes result/README only and keeps '
        'all raw private. No modeled private event/credentials/trace or '
        'Native data enter public JSON/ZIP. Actual PC source/stock3/WPA '
        'and ZIP bytes/CRC are verified, not actual Linux identity or '
        'closure. Normal21/AP3/journal13, ten completed old domains and '
        'event/type/frequency variants are not retested here. Physical '
        'P011/RF/FD3/watchdog/OFD/device/phone/performance/IP/DHCP/TLS/'
        'send/receive/whole Native restoration and production remain '
        'false. No old GO/device FAIL is upgraded to availability.\n').encode('ascii')
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
    output = BASE / 'results' / ('go-fresh-boundary-v63-r2-host-model-' +
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
        rb'GO_FRESH_BOUNDARY_V63_R2_HOST_PASS domains=(2) refusals=(2) full_runs=(2) '
        rb'interface_fresh=(1) uncertain_close_once=(1) old10_replayed=(0) rf_physical=0\r?\n', stdout)
    counts = tuple(int(value) for value in marker.groups()) if marker is not None else None
    stdout_reviewed = counts == (2, 2, 2, 1, 1, 0)
    stderr_reviewed = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = complete and invoked and code == 0 and not timeout and stdout_reviewed and stderr_reviewed
    value = dict(schema='go-fresh-boundary-v63-r2-host', selected_method=METHOD, selected_method_count=1,
        new_method_invocations=int(invoked), old_test_method_invocations=0, old_wrapper_invocations=0,
        source_manifest_count=len(graphs), loaded_source_graph_count=2 if passed else None,
        declared_model_domain_count=2, modules_per_loaded_graph=17, source_graphs=graphs,
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
        original63_method_replayed=False, original63_completed_ten_domains_replayed=False,
        original63_whole_method_passed=False, original63_combined_twelve_domain_pass_claimed=False,
        original63_failure_evidence_path='results/go-fresh-boundary-v63-host-model-20261002-212107-e8bb57ca',
        declared_original63_failed_method_and_partial_evidence_retained=True,
        native_original_loader_entry_store_native_bootstrap_host_model_tested=passed,
        actual_native_function_wrapped_or_replaced=False,
        modeled_validate_counter_forwards_original_and_requires_actual_snapshot_caller=True,
        modeled_counter_used_as_success_or_permission=False,
        actual_core_snapshot_or_canonical_or_grant_or_success_result_injected=False,
        modeled_stack_hook_requires_actual_native_namespace_self_and_ordered_frames=True,
        earlier_channel_current_or_caps_gate_modified=False,
        interface_current_fresh_extra_netdev_before_create_refusal_host_model_tested=passed,
        original_watchdog_live_then_restore_intent_pending_host_model_tested=passed,
        uncertain_close_same_error_once_no_retry_closed_false_host_model_tested=passed,
        semantic_pending_not_conflated_with_known_identity_or_missing_marker_host_model_tested=passed,
        optional_private_fd2_output_bounded_not_business_success_requirement_host_model_tested=passed,
        actual_business_refusal_claimed_from_diagnostic_writer=False,
        all_domains_claimed_pending_false=False,
        normal21_or_other_original_ten_domains_retested=False,
        declared_new_full_run_count=2, declared_refusal_count=2,
        declared_interface_fresh_refusal_count=1, declared_uncertain_close_domain_count=1,
        observed_counts=counts, case_names=('interface_extra', 'close_unknown'),
        every_event_type_or_status_mutation_variant_tested=False,
        single_middle_sample_claimed_equivalent_to_removed_temporal_sample=False,
        original_session_until_model_expected=301.0, original_entry_slice_deadline_model_expected=4.0,
        actual_p011_active75_or_baseline15_deadline_measured=False,
        actual_native_create_or_group_add_or_delete_requested=False,
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



