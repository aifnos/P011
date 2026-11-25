"""One new fixed v61 Proc diagnostic HOST method; ROOT execution only.

Twenty-nine private inputs retain current GO60 plus parent58 Native/F bytes for
SOURCE normalization only. One -I -B child runs seven model constructor domains
and actual ProcReader/Native refusals, firstpair/pure formatter/typed denials/
private diagnostic tail. No baseline/run/reserve/actors/pins/fork/RF/restore
or prior57/59/old method executes. Semantic unknown and physical unknown stay
separate; uncertain close remains pending. Quotas/caps/OR/gates are unchanged.
Only six fixed helper FunctionDefs load. Physical P011/performance/phone/full
Native restoration remains false. ROOT reviews and performs first execution.
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
CHECKER = 'host/go_proc_diagnostic_v61_check.py'
TEST = 'tests/test_go_proc_diagnostic_v61.py'
TEST_SHA = 'c2aeeeca3dfffa058e41a82f1c458535cad02e95b9999016693a5dce0ebc3b53'
TEST_BYTES = 32742
HELPER = 'tests/test_go_bootstrap_native_v34_r4.py'
HELPER_SHA = '3574ad5f729162ef6a26e8f4f133210bcec6bcc8e2f74c99d1355b67974cd8ef'
HELPER_BYTES = 32468
FUNCTIONS = ('fixed', 'tripwires', 'load_model', 'failure_code', 'failure_frames', 'diagnostic')
METHOD = 'GoProcDiagnosticV61Tests.test_actual_proc_unknown_first_pair_and_private_formatter_bounds_without_radio'
MODEL = 'tests/go_bootstrap_host_model_v34_r3.py'
MODEL_SHA = 'd8c07c9aa2e5e7c7c009f9411d7cb6ad3f820b12273639aad96526738dc6358f'
MODEL_BYTES = 25155
PLAN = 'host/go_proc_diagnostic_v60_source_manifest.json'
PLAN_SHA = 'c2be8155c68594d2baa863c5ff6a99b38f6e231c32eb79bb2f94aeac77a210cf'
PLAN_BYTES = 3956
PARENT_PLAN = 'host/go_baseline_budget_v58_source_manifest.json'
PARENT_PLAN_SHA = '0c987d6e667a0d4adce867b121493436f9bf2ba11380acc97e11efbf320a30a0'
PARENT_PLAN_BYTES = 3957
DELTA_MODULES = ('mta_go_executor', 'mta_go_native')
CHILD_SECONDS = 120
EXPECTED_INPUTS = 29
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


def diagnostic_source_bounds(old_native, new_native, old_executor, new_executor):
    """SOURCE AST normalization only; no old graph algorithms execute."""
    native = [ast.parse(raw) for raw in (old_native, new_native)]
    executor = [ast.parse(raw) for raw in (old_executor, new_executor)]
    for tree in native + executor:
        if not tree.body or not isinstance(tree.body[0], ast.Expr) or not isinstance(tree.body[0].value, ast.Constant):
            raise ValueError('HOST source documentation shape')
        tree.body.pop(0)
    def method(tree, cls, name):
        owner = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls]
        rows = [n for n in owner[0].body if isinstance(n, ast.FunctionDef) and n.name == name] if len(owner) == 1 else []
        if len(rows) != 1: raise ValueError('HOST fixed method changed')
        return rows[0]
    ctor = method(native[1], 'NativeGoResources', '__init__')
    assignment = [n for n in ctor.body if isinstance(n, ast.Assign) and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Attribute) and isinstance(n.targets[0].value, ast.Name)
        and n.targets[0].value.id == 'self' and n.targets[0].attr == 'last_proc_failure_v60'
        and isinstance(n.value, ast.Constant) and n.value.value is None]
    if len(assignment) != 1: raise ValueError('HOST original first pair constructor')
    ctor.body.remove(assignment[0])
    old_proc, new_proc = (method(tree, 'NativeGoResources', '_proc') for tree in native)
    old_if = [n for n in old_proc.body if isinstance(n, ast.If)]
    new_if = [n for n in new_proc.body if isinstance(n, ast.If)]
    if len(old_if) != 1 or len(new_if) != 1 or ast.dump(old_if[0].test) != ast.dump(new_if[0].test):
        raise ValueError('HOST original Proc refusal predicate changed')
    if len(new_if[0].body) != 2 or not isinstance(new_if[0].body[0], ast.Try):
        raise ValueError('HOST diagnostic capture shape')
    new_if[0].body.pop(0)
    if ast.dump(native[0], include_attributes=False) != ast.dump(native[1], include_attributes=False):
        raise ValueError('HOST other Native algorithm changed')
    added = [n for n in executor[1].body if isinstance(n, ast.FunctionDef) and n.name == '_proc_failure_text_v60']
    if len(added) != 1: raise ValueError('HOST formatter changed')
    executor[1].body.remove(added[0])
    functions = [[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'bootstrap'] for tree in executor]
    if any(len(rows) != 1 for rows in functions): raise ValueError('HOST original bootstrap function')
    heads = [[n for n in ast.walk(rows[0]) if isinstance(n, ast.Assign)
        and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'head']
        for rows in functions]
    if any(len(rows) != 2 for rows in heads): raise ValueError('HOST original private head changed')
    if len([n for n in ast.walk(heads[1][0]) if isinstance(n, ast.Call) and
            isinstance(n.func, ast.Name) and n.func.id == '_proc_failure_text_v60']) != 1:
        raise ValueError('HOST formatter head not used')
    if not any(isinstance(n, ast.Constant) and n.value == 1024 for n in ast.walk(heads[1][1])):
        raise ValueError('HOST head limit changed')
    for before, after in zip(heads[0], heads[1]): after.value = copy.deepcopy(before.value)
    if ast.dump(executor[0], include_attributes=False) != ast.dump(executor[1], include_attributes=False):
        raise ValueError('HOST other executor algorithm changed')


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
            ('v60_loaded', PLAN, PLAN_SHA, PLAN_BYTES)):
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
    diagnostic_source_bounds(original_source['mta_go_native'], current_source['mta_go_native'],
        original_source['mta_go_executor'], current_source['mta_go_executor'])
    distinct_sources = {row['path'] for item in graphs for row in item['sources']}
    if len(distinct_sources) != 19: raise ValueError('graph_union_changed')
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
        'One new v61 HOST component method loads actual GO60 Loader/F Entry/'
        'neutral CLIENT Store/bound ProcReader/GO Bootstrap constructors under '
        'the fixed syscall/FD/Proc/clock model. Seven independent domains make '
        'eight actual Native._proc refusals: expected argv change, missing '
        'mandatory stat, actual local Reader deadline, and physical-modeled '
        'close followed by EIO. Native still rejects native_actor_unknown. Six '
        'domains retain the actual first observation/Reader pair; diagnostic '
        'allocation failure remains best effort/unavailable, never a new error. '
        'A second actual rejection cannot overwrite the first pair. One actual '
        'neutral accounting CLEANUP generation is latest data only: match0 is '
        'explicitly not PRIMARY causation or GO restoration permission. The '
        'original Reader creates its actual observations/generations/FD tickets/'
        'raw/error and resource accounting; no observation or live flag is '
        'injected. Semantic unknown may have physical-model closed tickets; '
        'uncertain close instead keeps Reader pending and generation unknown/'
        'late, original close error and no retry. These are modeled syscall '
        'facts, not physical EBADF/native restoration evidence. '
        'Actual F pure formatter is exercised with IO/clock/authentication/'
        'owns_generation/history_closed tripwires, eight typed error/errno '
        'sanitation inputs and eight malformed shapes. Foreign repr/str/bool/'
        'code/errno/foreign-pair length access must not run; every formatter '
        'tripwire mock must have call_count0 even when unavailable is expected. '
        'Those malformed fields and long error/'
        'phase values are explicit deny-only diagnostic data, never a producer '
        'or grant. Only the actual AST-selected F diagnostic tail is compiled '
        'for output, not F.bootstrap business code or run. Three private FD2 '
        'write attempts cover ordinary output, 1024-byte head plus bounded '
        '16384-byte total, and write failure preserving result1. No private '
        'Proc values, traceback, filenames, raw Native bytes or identifiers '
        'are printed by this test or published in success raw. Parent GO58 '
        'Native/F bytes are SOURCE-only normalization inputs: original OR/'
        'short-circuit/refusal and all other algorithms remain unchanged. '
        'Only current GO60 algorithms load; old source algorithms, old tests/'
        'checkers/START and prior57/59 methods do not execute. Only six fixed '
        'helper FunctionDefs load. Twenty-nine immutable private inputs, one '
        '-I -B child, HOST120, no retry, original quotas/caps and raw streams '
        'are retained. Success requires fixed numeric 7/8/6/1/1/1/8/8/1/3/'
        '1024/16384 marker, Ran1/OK, exit0 and no timeout; only then four public '
        'members include reviewed numeric raw. Failure keeps all raw private '
        'and publishes result/README only. Actual PC stock-three/WPA/source '
        'bytes and ZIP CRC are checked; Linux/Proc/FDs/clock/Python/CLI '
        'identities remain models. No baseline snapshot, actors/pins, '
        'GoBootstrap.run/reserve, canonical publication, fork, RF, GO group, '
        'restore, performance, phone/IP/DHCP/TLS/send/receive test runs. P011 '
        'availability and complete Native restoration remain false. This '
        'component does not upgrade any prior actual GO/device failure or '
        'combine prior component results into a full PASS.\n').encode('ascii')
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
    output = BASE / 'results' / ('go-proc-diagnostic-v61-host-model-' +
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
        rb'GO_PROC_DIAGNOSTIC_V61_HOST_PASS cases=(7) refused=(8) pairs=(6) first_unchanged=(1) '
        rb'cleanup_match0=(1) unknown_late=(1) shape_denied=(8) sanitized=(8) capture_unavailable=(1) '
        rb'fd2_writes=(3) max_head=(1024) max_write=(16384) rf_calls=0\r?\n', stdout)
    counts = tuple(int(value) for value in marker.groups()) if marker is not None else None
    stdout_reviewed = counts == (7, 8, 6, 1, 1, 1, 8, 8, 1, 3, 1024, 16384)
    stderr_reviewed = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = complete and invoked and code == 0 and not timeout and stdout_reviewed and stderr_reviewed
    value = dict(schema='go-proc-diagnostic-v61-host', selected_method=METHOD, selected_method_count=1,
        new_method_invocations=int(invoked), old_test_method_invocations=0, old_wrapper_invocations=0,
        source_manifest_count=len(graphs), loaded_source_graph_count=1 if invoked else 0,
        modules_per_loaded_graph=17, source_graphs=graphs,
        source_count=len({row['path'] for graph in graphs for row in graph['sources']}),
        loaded_source_count=17 if invoked else 0, parent_native_executor_source_only_count=2,
        exact_lineage_delta_module_names=DELTA_MODULES,
        test_sha256=TEST_SHA, test_bytes=TEST_BYTES, model_sha256=MODEL_SHA, model_bytes=MODEL_BYTES,
        helper_sha256=HELPER_SHA, helper_bytes=HELPER_BYTES, helper_function_names=FUNCTIONS,
        helper_definition_inventory_source_verified=source_verified,
        helper_functions_only_loaded=passed, old_test_class_or_method_loaded=False,
        parent_source_graph_or_old_native_executor_algorithm_executed=False,
        source_original_native_proc_OR_and_shortcircuit_unchanged_verified=source_verified,
        source_other_native_executor_algorithm_bodies_unchanged_verified=source_verified,
        checker_sha256=hashlib.sha256(own).hexdigest(), source_integrity_verified=source_verified,
        python35_syntax_verified=source_verified, verification_error=verification_error,
        snapshot_error=snapshot_error, launch_error=launch_error, host_method_passed=passed,
        host_exit=code, timeout=timeout, host_child_timeout_seconds=CHILD_SECONDS, host_elapsed_seconds=elapsed,
        input_snapshot_complete=complete, input_snapshot_entry_count=len(input_rows), expected_input_snapshot_entry_count=EXPECTED_INPUTS,
        inputs=input_rows, child_reads_private_snapshot=invoked, child_python_isolated_mode=True,
        original_failed_source_or_raw_modified=False, old_actors_pins_frequency_or_full_flow_replayed=False,
        prior57_or59_methods_replayed=False,
        native_original_loader_entry_constructor_algorithm_host_model_tested=passed,
        native_actual_proc_reader_unknown_observations_host_model_tested=passed,
        actual_proc_observation_or_generation_or_live_flag_injected=False,
        native_original_proc_refusal_code_preserved_host_model_tested=passed,
        native_first_original_pair_and_second_no_overwrite_host_model_tested=passed,
        native_best_effort_capture_failure_preserves_original_refusal_host_model_tested=passed,
        semantic_unknown_not_conflated_with_physical_pending_host_model_tested=passed,
        uncertain_close_original_error_pending_unknown_late_no_retry_host_model_tested=passed,
        actual_neutral_cleanup_generation_latest_match0_host_model_tested=passed,
        latest_match0_claimed_as_primary_cause=False,
        cleanup_accounting_lane_declared_as_go_restoration_permission=False,
        formatter_pure_no_io_clock_source_or_history_method_host_model_tested=passed,
        formatter_typed_error_errno_foreign_tripwire_sanitation_host_model_tested=passed,
        formatter_malformed_shape_unavailable_host_model_tested=passed,
        actual_diagnostic_tail_only_ast_extracted_host_model_tested=passed,
        diagnostic_tail_compiled_as_business_bootstrap_or_run=False,
        private_fd2_one_write_per_invocation_head1024_total16384_host_model_tested=passed,
        diagnostic_writer_failure_does_not_replace_result_host_model_tested=passed,
        synthetic_long_phase_errors_and_malformed_fields_are_deny_only=True,
        synthetic_diagnostic_errors_claimed_as_actual_business_cause=False,
        declared_fresh_model_case_count=7, declared_native_proc_refusal_count=8,
        declared_actual_first_pair_domain_count=6, declared_second_no_overwrite_count=1,
        declared_cleanup_latest_match0_count=1, declared_uncertain_close_domain_count=1,
        declared_shape_refusal_count=8, declared_error_sanitation_count=8,
        declared_capture_unavailable_count=1, declared_private_write_attempts=3,
        observed_counts=counts,
        case_names=('first_and_cleanup', 'record_disappeared', 'reader_deadline',
            'close_uncertainty', 'capture_best_effort', 'formatter_denials', 'private_fd2_bound'),
        original_session_until_model_expected=301.0, original_entry_slice_deadline_model_expected=4.0,
        native_stage_scope_model_expected=16.0, reader_local_deadline_case_expected=4.0,
        actual_p011_active45_or_baseline15_deadline_measured=False,
        native_positive_grant_or_canonical_stubbed=False, native_bootstrap_run_tested=False,
        native_baseline_snapshot_completed=False, native_go_store_reservation_or_publication_tested=False,
        native_go_creation_same8_to9_and_phase_cas_tested=False,
        native_ack_echo_creator_or_successful_group_tested=False,
        native_complete_restore_tested=False, modeled_all_resource_pending_false_claimed=False,
        modeled_uncertain_close_retains_pending_host_model_tested=passed,
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
