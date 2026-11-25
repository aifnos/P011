"""Fixed HOST66 pure diagnostic checker; ROOT alone authorizes the first run.

One future -I -B child loads the current exact 17 source definition domain and
only new timing32/stat6diff/FD2 diagnostic helpers. Exact-class object.__new__
data are synthetic and have no source authenticity, producer or business
permission. No old method, Loader load, Bootstrap constructor/run, reservation,
RF, process or restoration algorithm runs. Failure raw remain private. The
v65-r2 map/test pins and strict completion marker are immutable inputs.
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
CHECKER = 'host/go_private_diagnostic_v66_check.py'
TEST = 'tests/test_go_private_diagnostic_v66.py'
TEST_SHA = '33b3712873c75cc4370f8ec09cfef8354f3dd1287bc7584b4ff288263d4336b8'
TEST_BYTES = 37105
METHOD = 'GoPrivateDiagnosticV66Tests.test_only_new_stat6diff_timing32_selection_and_private_utf8_bounds'
PLAN = 'host/go_private_diagnostic_v65_r2_source_manifest.json'
PLAN_SHA = '99a2329c18efeb26baf9bab3a6249e14168440a2ee87430720317be0caadba36'
PLAN_BYTES = 3968
PARENT_PLAN = 'host/go_fresh_boundary_v62_source_manifest.json'
PARENT_PLAN_SHA = 'b959ae92e6ef048b3724e716e09503a7607f0b07e6eef5f4e14be71bd545e842'
PARENT_PLAN_BYTES = 3955
MODULES = ('p011_json', 'mta_ip', 'mta_client_tmp_alias', 'mta_p2p_client_init',
    'mta_client_resource_budget', 'mta_client_proc', 'mta_client_journal_codec',
    'mta_client_coordination', 'mta_client_files', 'mta_client_pending', 'mta_client_store',
    'mta_go_process_owner', 'mta_go_deployment', 'mta_go_executor', 'mta_go_bootstrap_store',
    'mta_go_native', 'mta_go_bootstrap')
DELTA_MODULES = ('mta_go_executor', 'mta_go_native')
CHILD_SECONDS, EXPECTED_INPUTS = 120, 23


def safe(path):
    return (type(path) is str and path and not path.startswith(('/', '\\')) and
        ':' not in path and '\\' not in path and
        all(part not in ('', '.', '..') for part in path.split('/')))


def fixed(path, sha, size):
    if (not safe(path) or type(size) is not int or not 1 <= size <= 8388608 or
            type(sha) is not str or re.fullmatch('[0-9a-f]{64}', sha) is None):
        raise ValueError('input_identity_changed')
    raw = (BASE / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('input_changed')
    return raw


def add(inputs, path, raw):
    if path in inputs and inputs[path] != raw:
        raise ValueError('input_identity_conflict')
    inputs[path] = raw
    return raw


def verify(inputs):
    """ROOT execution: SOURCE AST/hash only, no target/test import here."""
    raw_test = add(inputs, TEST, fixed(TEST, TEST_SHA, TEST_BYTES))
    graphs = []
    for label, path, sha, size in (
            ('v62_parent_source_only', PARENT_PLAN, PARENT_PLAN_SHA, PARENT_PLAN_BYTES),
            ('v65_r2_current_definitions', PLAN, PLAN_SHA, PLAN_BYTES)):
        graph = json.loads(add(inputs, path, fixed(path, sha, size)))
        if (type(graph) is not dict or set(graph) != {'schema', 'sources'} or
                graph['schema'] != 'go-frequency-v46-host' or
                type(graph['sources']) is not list or
                tuple(row['module'] for row in graph['sources']) != MODULES or
                any(set(row) != {'module', 'path', 'sha256', 'bytes'} for row in graph['sources'])):
            raise ValueError('graph_changed')
        graphs.append(dict(label=label, source_manifest_path=path,
            source_manifest_sha256=sha, source_manifest_bytes=size, sources=graph['sources']))
    parent, current = (graph['sources'] for graph in graphs)
    if tuple(after['module'] for before, after in zip(parent, current) if before != after) != DELTA_MODULES:
        raise ValueError('graph_lineage_changed')
    target = {}
    for row in current:
        raw = add(inputs, row['path'], fixed(row['path'], row['sha256'], row['bytes']))
        parsed = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(parsed)):
            raise ValueError('target_assert_changed')
        target[row['module']] = raw
        if row['module'] == 'mta_go_deployment':
            names = [ast.literal_eval(node.value) for node in parsed.body if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'MODULES' for t in node.targets)]
            if names != [MODULES]:
                raise ValueError('loader_graph_changed')
    for row in parent:
        if row['module'] in DELTA_MODULES:
            add(inputs, row['path'], fixed(row['path'], row['sha256'], row['bytes']))
    if len({row['path'] for graph in graphs for row in graph['sources']}) != 19:
        raise ValueError('source_union_changed')
    parsed = ast.parse(raw_test.decode('utf-8'))
    names = [cls.name + '.' + method.name for cls in parsed.body if isinstance(cls, ast.ClassDef)
        for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')]
    if names != [METHOD]:
        raise ValueError('unique_method_changed')
    bindings = {'PLAN', 'PLAN_SHA', 'PLAN_BYTES', 'PARENT_PLAN', 'PARENT_PLAN_SHA',
        'PARENT_PLAN_BYTES', 'MODULES', 'DELTA_MODULES'}
    constants = {target.id: ast.literal_eval(node.value) for node in parsed.body if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name) and target.id in bindings}
    expected = dict(PLAN=PLAN, PLAN_SHA=PLAN_SHA, PLAN_BYTES=PLAN_BYTES,
        PARENT_PLAN=PARENT_PLAN, PARENT_PLAN_SHA=PARENT_PLAN_SHA, PARENT_PLAN_BYTES=PARENT_PLAN_BYTES,
        MODULES=MODULES, DELTA_MODULES=DELTA_MODULES)
    if constants != expected:
        raise ValueError('test_binding_changed')
    for node in ast.walk(parsed):
        if isinstance(node, ast.Import) and any(a.name.startswith(('test_', 'mta_', 'p011_')) for a in node.names):
            raise ValueError('unexpected_fixture_import')
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith(('test_', 'mta_', 'p011_')):
            raise ValueError('unexpected_fixture_import')
    if len(inputs) != EXPECTED_INPUTS:
        raise ValueError('input_inventory_changed')
    # Child verifies the whole Native/F SOURCE inverse before it executes any
    # current definitions. The two old bodies are never executed or imported.
    selected = [method for cls in parsed.body if isinstance(cls, ast.ClassDef)
        for method in cls.body if isinstance(method, ast.FunctionDef)
        and cls.name + '.' + method.name == METHOD][0]
    if sum(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == '_source_delta' for node in ast.walk(selected)) != 1:
        raise ValueError('source_inverse_check_changed')
    return graphs


def snapshot(output, inputs):
    project = output / 'private-inputs' / 'project'
    working = project / 'working' / 'MtaP011-v0.1'
    facts = []
    for path, raw in sorted(inputs.items()):
        destination = (working / path).resolve()
        if not destination.is_relative_to(project.resolve()):
            raise ValueError('snapshot_escape')
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        if destination.read_bytes() != raw:
            raise ValueError('snapshot_changed')
        facts.append(dict(path=path, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    if len(facts) != EXPECTED_INPUTS:
        raise ValueError('snapshot_inventory_changed')
    return working, facts


def publish(output, value, stdout, stderr, passed):
    result = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (
        'One new HOST66 pure diagnostic method:12 timing categories,33 stat '
        'categories including10 real-parser change vectors,9 domain categories '
        'and4 diagnostic-tail output categories. The capacity-fill observer '
        'makes160 clock callbacks. The actual current private17 source definitions '
        'are loaded once, with running F before private Proc. One separate '
        'ordinary Proc definition simulates the distinct sys.modules domain '
        '(18 total module-definition executions). This is fixed Loader SOURCE '
        'shape, NOT actual Loader.load/authentication. Exact-class object.__new__ '
        'data and stat RawRecord bytes '
        'are explicit synthetic diagnostic fixtures, NOT genuine producer/permission '
        'or original business observations. No Loader.load/Entry.prepare/Store or '
        'Bootstrap constructor, run/reserve, Native business gate, baseline, fork, '
        'RF or restoration runs. Only new stat6diff/timing32/selection and actual '
        'F diagnostic tail helpers run; actual snapshot except/finally is called '
        'only with an initial synthetic validate failure before any file/Proc '
        'operation. Parent Native/F are SOURCE-only inverse comparison inputs, '
        'not algorithms. No old TestCase/checker/method loads or executes. '
        'Twenty-three immutable private inputs; one -I -B child; HOST120; no '
        'retry. CMD is separately verified, not one of the23 private inputs. '
        'The fixed numeric completion marker and Ran1/OK plus exit0 and '
        'no timeout are required before four public ZIP members may include '
        'reviewed raw. Otherwise raw stay private and only result/README publish. '
        'Actual PC source bytes, raw and ZIP CRC are checked. All physical Linux, '
        'P011, actual process, FD/OFD, RF, performance, phone, business and full '
        'restoration claims remain false. No quotas/caps/unknowns are changed. '
        'Private paths/PIDs/comm/trace/stat values are not printed or in the '
        'public ZIP. A formatter result is never a kernel identity/rootmeta '
        'proof or a primary business cause. Existing actual64 FAIL/pending and '
        'all earlier result files are preserved. Old65 was never executed and '
        'its ordinary-Proc/private-domain SOURCE defect is not promoted. '
        'A zero PID-diff bit follows original parser/path identity; a changed '
        'raw PID under the same path is unavailable, not a positive PID proof.\n').encode('ascii')
    (output / 'result.json').write_bytes(result)
    (output / 'README.txt').write_bytes(readme)
    expected = {'result.json': result, 'README.txt': readme}
    if passed:
        expected.update({'stdout.raw': stdout, 'stderr.raw': stderr})
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in expected.items():
            bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != list(expected) or bundle.testzip() is not None:
            raise ValueError('zip_changed')
        for name, wanted in expected.items():
            raw, info = bundle.read(name), bundle.getinfo(name)
            if (raw != wanted or info.file_size != len(raw) or
                    info.CRC != zlib.crc32(raw) & 0xffffffff or (output / name).read_bytes() != raw):
                raise ValueError('zip_member_changed')
    return archive


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY fixed HOST66; no device/network/path arguments')
        return 2
    output = BASE / 'results' / ('go-private-diagnostic-v66-host-model-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    own = Path(__file__).read_bytes()
    inputs, graphs, source_verified = {CHECKER: own}, [], False
    verification_error = snapshot_error = launch_error = None
    try:
        graphs = verify(inputs)
        source_verified = True
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, UnicodeError):
        verification_error = 'fixed_source_invalid'
    child_base, input_rows = None, []
    try:
        child_base, input_rows = snapshot(output, inputs)
    except (OSError, ValueError):
        snapshot_error = 'private_snapshot_invalid'
    complete = source_verified and snapshot_error is None
    stdout, stderr, code, timeout, invoked = b'', b'', None, False, False
    started = time.monotonic()
    if complete:
        env = dict(os.environ)
        env.pop('PYTHONPATH', None)
        env.pop('PYTHONSTARTUP', None)
        try:
            child = subprocess.run([sys.executable, '-I', '-B', str(child_base / TEST), '-q', METHOD],
                cwd=str(child_base), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=CHILD_SECONDS, check=False)
            stdout, stderr, code, invoked = child.stdout, child.stderr, child.returncode, True
        except subprocess.TimeoutExpired as error:
            stdout, stderr, timeout, invoked = error.stdout or b'', error.stderr or b'', True, True
        except OSError:
            launch_error = 'host_child_not_started'
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    marker = re.fullmatch(rb'HOST66_PRIVATE_DIAGNOSTIC timing=([0-9]+) stat=([0-9]+) domains=([0-9]+) '
        rb'vectors=([0-9]+) capacity_callbacks=([0-9]+) fd2=([0-9]+) private_sources=([0-9]+) '
        rb'old_methods=([0-9]+)\r?\n', stdout)
    counts = tuple(int(item) for item in marker.groups()) if marker else None
    stdout_reviewed = counts == (12, 33, 9, 10, 160, 4, 17, 0)
    stderr_reviewed = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = complete and invoked and code == 0 and not timeout and stdout_reviewed and stderr_reviewed
    value = dict(schema='go-private-diagnostic-v66-host', selected_method=METHOD, selected_method_count=1,
        new_method_invocations=int(invoked), old_test_method_invocations=0, old_wrapper_invocations=0,
        host_method_passed=passed, host_exit=code, timeout=timeout, host_elapsed_seconds=elapsed,
        host_child_timeout_seconds=CHILD_SECONDS, source_manifest_count=len(graphs), source_graphs=graphs,
        source_count=len({row['path'] for graph in graphs for row in graph['sources']}),
        loaded_private_source_definition_count=17 if passed else None,
        ordinary_proc_definition_count=1 if passed else None,
        total_module_definition_execution_count=18 if passed else None,
        parent_source_algorithms_executed=False,
        input_snapshot_complete=complete, input_snapshot_entry_count=len(input_rows),
        expected_input_snapshot_entry_count=EXPECTED_INPUTS, inputs=input_rows,
        child_reads_private_snapshot=invoked, child_python_isolated_mode=True,
        checker_sha256=hashlib.sha256(own).hexdigest(), test_sha256=TEST_SHA, test_bytes=TEST_BYTES,
        source_integrity_verified=source_verified, python35_syntax_verified=source_verified,
        verification_error=verification_error, snapshot_error=snapshot_error, launch_error=launch_error,
        exact_lineage_delta_module_names=DELTA_MODULES, observed_counts=counts,
        exact_class_objectnew_data_synthetic=True, exact_rawrecord_stat_bytes_synthetic=True,
        loader_source_mixed_running_f_private_proc_shape_simulated=True,
        actual_loader_runtime_or_manifest_authentication_tested=False,
        current_vs_parent_whole_source_inverse_verified_in_child=passed,
        timing_category_count=12 if passed else None, stat_category_count=33 if passed else None,
        mixed_domain_category_count=9 if passed else None, real_parser_change_vector_count=10 if passed else None,
        capacity_fill_clock_callback_count=160 if passed else None,
        diagnostic_tail_case_count=4 if passed else None,
        formatter_no_sampling_io_clock_history_method_calls_checked=passed,
        initial_synthetic_validation_failure_finally_only_tested=passed,
        successful_native_snapshot_or_current_business_gate_tested=False,
        source_or_original_business_identity_proven=False, original_loader_or_entry_constructor_tested=False,
        private_diagnostic_helpers_host_component_tested=passed,
        actual_diagnostic_tail_only_ast_extracted_host_component_tested=passed,
        business_dispatch_or_run_called=False, source_admission_or_producer_or_ready_injected=False,
        rootmeta_identity_or_primary_cause_claimed=False, original_quota_expanded=False,
        original_active_cap_renewed=False, unknown_resource_cleared=False,
        native_snapshot_or_reserve_or_rf_or_restore_tested=False,
        p011_go_service_available=False, p011_ip_dhcp_tls_send_receive_available=False,
        whole_native_go_or_restore_pass_claimed=False, actual_p011_restore_verified=False,
        actual_linux_proc_or_socket_tested=False, actual_process_or_fd_closure_tested=False,
        device_accessed=False, rf_requested=False, phone_tested=False,
        actual_business_failure_or_performance_measured=False,
        private_key_or_user_id_public=False, raw_stat_path_or_traceback_in_public_zip=False,
        stdout_fixed_marker_reviewed=stdout_reviewed, unittest_stderr_reviewed=stderr_reviewed,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        public_raw_included=passed, public_zip_member_count=4 if passed else 2)
    archive = publish(output, value, stdout, stderr, passed)
    print(json.dumps(dict(passed=passed, host_exit=code, timeout=timeout, elapsed_seconds=elapsed,
        result_zip=str(archive), zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())))
    return 0 if passed else 2 if verification_error or snapshot_error or launch_error else 1


if __name__ == '__main__':
    sys.exit(main())
