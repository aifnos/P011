"""PC-only first-run wrapper for one new CLIENT51/GO52 paired HOST method.

57 fixed private inputs; two disjoint source/type domains; ten paired cases.
No old test method, RF, device, full collect, bootstrap run or reservation.
Only ROOT executes this wrapper. Original deadlines/quotas and HOST120 remain.
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
CHECKER = 'host/proc_comm_vanish_v53_check.py'
TEST = 'tests/test_proc_comm_vanish_v53.py'
TEST_SHA = '3a5fa0233b90e3f3709a68aceec1805c92c484b548a1ebc396545e283fc01e96'
TEST_BYTES = 20500
METHOD = 'ProcCommVanishV53Tests.test_paired_original_comm_open_absence_and_non_absence_refusals'
CLIENT_PLAN = 'host/client_readonly_proc_vanish_v51_source_manifest.json'
CLIENT_PLAN_SHA = '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60'
CLIENT_PLAN_BYTES = 8096
CLIENT_PREVIOUS = 'host/client_readonly_diagnostic_v47_source_manifest.json'
CLIENT_PREVIOUS_SHA = '212caa6f86340d6fcfedee5714d8df5226e1eaf1e151b16c0742ab900c4ffbe0'
CLIENT_PREVIOUS_BYTES = 8095
GO_PLAN = 'host/go_proc_vanish_v52_source_manifest.json'
GO_PLAN_SHA = '1a4046f95ddcebfc6bbcac17df4518f0ba33759ce9f64484c569667ca5343311'
GO_PLAN_BYTES = 3952
GO_PREVIOUS = 'host/go_pin_digest_v49_source_manifest.json'
GO_PREVIOUS_SHA = '4b1f0322295f5612f70ddca4797d223b919e775a4b23a4218cbe48c66451a110'
GO_PREVIOUS_BYTES = 3951
HELPER = 'tests/test_go_bootstrap_native_v34_r4.py'
HELPER_SHA = '3574ad5f729162ef6a26e8f4f133210bcec6bcc8e2f74c99d1355b67974cd8ef'
HELPER_BYTES = 32468
FUNCTIONS = ('fixed', 'tripwires', 'load_model', 'failure_code', 'failure_frames', 'diagnostic')
MODEL = 'tests/go_bootstrap_host_model_v34_r3.py'
MODEL_SHA = 'd8c07c9aa2e5e7c7c009f9411d7cb6ad3f820b12273639aad96526738dc6358f'
MODEL_BYTES = 25155
CHILD_SECONDS = 120
EXPECTED_INPUTS = 57
STOCK = (
    ('/usr/bin/Z03', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/Z03',
        'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a', 4103844),
    ('/usr/bin/control_engine', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/control_engine',
        '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d', 163184),
    ('/usr/bin/zyb_z03_launch.sh', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/zyb_z03_launch.sh',
        '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b', 1913))
WPA = ('native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant',
    'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301', 1351192)
CASES = ('open_enoent', 'open_eio', 'open_eacces', 'fd_fstat_enoent',
    'fd_read_enoent', 'close_enoent', 'tracked_proc_missing', 'tracked_image_missing',
    'mandatory_comm_missing', 'late_open_enoent')
GO_MODULES = ('p011_json', 'mta_ip', 'mta_client_tmp_alias', 'mta_p2p_client_init',
    'mta_client_resource_budget', 'mta_client_proc', 'mta_client_journal_codec',
    'mta_client_coordination', 'mta_client_files', 'mta_client_pending', 'mta_client_store',
    'mta_go_process_owner', 'mta_go_deployment', 'mta_go_executor', 'mta_go_bootstrap_store',
    'mta_go_native', 'mta_go_bootstrap')


def safe(path):
    return (type(path) is str and path and not path.startswith(('/', '\\')) and ':' not in path
        and '\\' not in path and all(p not in ('', '.', '..') for p in path.split('/')))


def fixed(path, digest, size):
    if not safe(path) and path not in {r[1] for r in STOCK}: raise ValueError('input_path_changed')
    if type(size) is not int or not 1 <= size <= 8388608 or re.fullmatch('[0-9a-f]{64}', digest) is None:
        raise ValueError('input_identity_changed')
    raw = (BASE / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest: raise ValueError('input_changed')
    return raw


def add(inputs, path, raw):
    if path in inputs and inputs[path] != raw: raise ValueError('input_identity_conflict')
    inputs[path] = raw
    return raw


def assigned(tree, name):
    return [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]


def verify(inputs):
    """No production/old test import; fixed source hash and AST inventory only."""
    raw_test = add(inputs, TEST, fixed(TEST, TEST_SHA, TEST_BYTES))
    raw_model = add(inputs, MODEL, fixed(MODEL, MODEL_SHA, MODEL_BYTES))
    raw_helper = add(inputs, HELPER, fixed(HELPER, HELPER_SHA, HELPER_BYTES))
    chosen = tuple(n.name for n in ast.parse(raw_helper).body
        if isinstance(n, ast.FunctionDef) and n.name in FUNCTIONS)
    if chosen != FUNCTIONS: raise ValueError('helper_definition_inventory_changed')
    graphs = {}
    for kind, new, old, changed, count, schema in (
            ('client', (CLIENT_PLAN, CLIENT_PLAN_SHA, CLIENT_PLAN_BYTES),
                (CLIENT_PREVIOUS, CLIENT_PREVIOUS_SHA, CLIENT_PREVIOUS_BYTES),
                'mta_client_baseline', 35, 'client-readonly-diagnostic-v47-source'),
            ('go', (GO_PLAN, GO_PLAN_SHA, GO_PLAN_BYTES),
                (GO_PREVIOUS, GO_PREVIOUS_SHA, GO_PREVIOUS_BYTES),
                'mta_go_native', 17, 'go-frequency-v46-host')):
        current = json.loads(add(inputs, new[0], fixed(*new)))
        previous = json.loads(add(inputs, old[0], fixed(*old)))
        if (type(current) is not dict or set(current) != set(previous) or current['schema'] != schema
                or any(current[k] != previous[k] for k in current if k != 'sources')):
            raise ValueError('graph_metadata_changed')
        rows, former = current['sources'], previous['sources']
        if (type(rows) is not list or len(rows) != count or len(former) != count
                or len({r['module'] for r in rows}) != count
                or [r['module'] for r in rows] != [r['module'] for r in former]
                or [r['module'] for r, p in zip(rows, former) if r != p] != [changed]
                or any(set(r) != {'module', 'path', 'sha256', 'bytes'} for r in rows)):
            raise ValueError('graph_delta_changed')
        parsed_sources = {}
        for row in rows:
            raw = add(inputs, row['path'], fixed(row['path'], row['sha256'], row['bytes']))
            tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
            if any(isinstance(n, ast.Assert) for n in ast.walk(tree)): raise ValueError('target_assert_changed')
            parsed_sources[row['module']] = tree
        modules = tuple(r['module'] for r in rows)
        target = 'mta_client_executor' if kind == 'client' else 'mta_go_deployment'
        if assigned(parsed_sources[target], 'MODULES') != [modules]: raise ValueError('native_graph_changed')
        if kind == 'go' and modules != GO_MODULES: raise ValueError('go_order_changed')
        graphs[kind] = rows
    unique = {(r['path'], r['sha256'], r['bytes']) for rows in graphs.values() for r in rows}
    if len(unique) != 45: raise ValueError('source_union_changed')
    for path, relative, digest, size in STOCK: add(inputs, relative, fixed(relative, digest, size))
    add(inputs, WPA[0], fixed(*WPA))
    tree = ast.parse(raw_test)
    names = [cls.name + '.' + fn.name for cls in tree.body if isinstance(cls, ast.ClassDef)
        for fn in cls.body if isinstance(fn, ast.FunctionDef) and fn.name.startswith('test_')]
    if names != [METHOD]: raise ValueError('method_inventory_changed')
    wanted = ('CLIENT_PLAN', 'CLIENT_PLAN_SHA', 'CLIENT_PLAN_BYTES', 'CLIENT_PREVIOUS',
        'CLIENT_PREVIOUS_SHA', 'CLIENT_PREVIOUS_BYTES', 'GO_PLAN', 'GO_PLAN_SHA', 'GO_PLAN_BYTES',
        'GO_PREVIOUS', 'GO_PREVIOUS_SHA', 'GO_PREVIOUS_BYTES', 'HELPER', 'HELPER_SHA', 'HELPER_BYTES',
        'FUNCTIONS', 'MODEL', 'MODEL_SHA', 'MODEL_BYTES', 'STOCK', 'WPA', 'CASES')
    actual = {name: assigned(tree, name) for name in wanted}
    if actual != {name: [globals()[name]] for name in wanted}: raise ValueError('test_binding_changed')
    for parsed in (tree, ast.parse(raw_model)):
        for node in ast.walk(parsed):
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
        'One new method, ten paired CLIENT51/GO52 cases in independent exact-type domains. '
        'The two graphs have 52 module slots and 45 unique pinned source files. Six old '
        'FunctionDefs and the fixed LinuxModel load, never an old TestCase/method/wrapper. '
        'CLIENT uses the actual neutral Store ctor/native budget binding, actual ProcReader, '
        'collector ctor and same original file/hash/parent checks for private pin preparation. '
        'Its actual _actors retains mandatory actors and fresh process exe-image pin checks. '
        'GO uses the actual GO17 Loader/F Entry/neutral Store/Bootstrap ctor and _actors; '
        'the positive does not repeat the passed v49 pin-digest round. Only the process-image '
        'disappearance refusal invokes actual Native._pins after native actors. '
        'Cases are original initial comm ENOENT, EIO, EACCES, acquired-FD fstat ENOENT, '
        'acquired-FD read ENOENT, close ENOENT, tracked Proc disappearance, tracked image '
        'disappearance, required comm disappearance and late initial ENOENT. Only the '
        'known initial comm-open absence may skip; original requested path/flags/caught '
        'identity/no FD/known absence inventory are retained. Required actor absence still '
        'refuses. Late return is checked against the same once-issued cap. Uncertain close '
        'never retries or clears unknown: Baseline records pending/closure false even if '
        '_actors returns, while Native preserves its original close exception and refuses '
        'another close. Known absence is not a physical-close certificate. '
        'No Actor/Proc/hash success, Native, canonical, grant or restored boolean is stubbed. '
        'Only syscall results, FD/kernel/Proc/clock and Python/CLI identity are explicit '
        'HOST models. CLIENT collect/STATUS/full snapshot, Bootstrap.run/reserve/publication, '
        'RF/GO creation/restore/IP/DHCP/phone are not executed or certified. Original quotas, '
        '300-second GO model until, private CLIENT stage5/GO stage10 and HOST120 stay fixed; '
        'no active deadline is renewed and no resource failure is washed. Actual PC archive '
        'source/WPA/stock bytes, private snapshot and ZIP bytes/CRC are checked. Device '
        'Linux/FD/OFD/fork/exec/watchdog/performance and actual restoration remain false. '
        '57 exact inputs include both immutable lineage maps. One -I -B child, one method, '
        'no retry. Original stdout/stderr remain private on failure. Only exact fixed numeric '
        'marker, Ran1/OK, child0 and no timeout permit the four-member result/README/raw ZIP; '
        'failure has two members. Public output has no user path/identifier/key/credential. '
        'Old passed methods and failed device/source/results are not changed or promoted.\n').encode('ascii')
    (output / 'result.json').write_bytes(result)
    (output / 'README.txt').write_bytes(readme)
    names = ['result.json', 'README.txt'] + (['stdout.raw', 'stderr.raw'] if passed else [])
    expected = {'result.json': result, 'README.txt': readme}
    if passed: expected.update({'stdout.raw': stdout, 'stderr.raw': stderr})
    archive = output / 'public-result.zip'
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
        print('PC_ONLY fixed paired actors HOST model; no device/network/path arguments')
        return 2
    output = BASE / 'results' / ('proc-comm-vanish-v53-host-model-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    own = Path(__file__).read_bytes()
    inputs, graphs, verified = {CHECKER: own}, {}, False
    verification_error = snapshot_error = launch_error = None
    try: graphs = verify(inputs); verified = True
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, UnicodeError): verification_error = 'fixed_source_invalid'
    child_base, input_rows = None, []
    try: child_base, input_rows = snapshot(output, inputs)
    except (OSError, ValueError): snapshot_error = 'private_snapshot_invalid'
    complete = verified and snapshot_error is None
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
    marker = re.fullmatch(rb'PROC_COMM_VANISH_V53_HOST_PASS paired_cases=10 graph_cases=20 known_open_skips=(2) refusals=(18) uncertain_close_attempts=(2) rf_calls=0\r?\n', stdout)
    counts = tuple(int(v) for v in marker.groups()) if marker is not None else None
    stdout_reviewed = counts == (2, 18, 2)
    stderr_reviewed = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = complete and invoked and code == 0 and not timeout and stdout_reviewed and stderr_reviewed
    value = dict(schema='proc-comm-vanish-v53-host', selected_method=METHOD, selected_method_count=1,
        new_method_invocations=int(invoked), old_test_method_invocations=0, old_wrapper_invocations=0,
        client_source_count=len(graphs.get('client', [])), go_source_count=len(graphs.get('go', [])),
        unique_source_count=45, sources=graphs, client_manifest_sha256=CLIENT_PLAN_SHA,
        client_manifest_bytes=CLIENT_PLAN_BYTES, go_manifest_sha256=GO_PLAN_SHA, go_manifest_bytes=GO_PLAN_BYTES,
        client_lineage_manifest_sha256=CLIENT_PREVIOUS_SHA, go_lineage_manifest_sha256=GO_PREVIOUS_SHA,
        test_sha256=TEST_SHA, test_bytes=TEST_BYTES, helper_sha256=HELPER_SHA, helper_bytes=HELPER_BYTES,
        helper_function_names=FUNCTIONS, model_sha256=MODEL_SHA, model_bytes=MODEL_BYTES,
        checker_sha256=hashlib.sha256(own).hexdigest(), source_integrity_verified=verified,
        python35_syntax_verified=verified, source_single_delta_lineage_verified=verified,
        verification_error=verification_error, snapshot_error=snapshot_error, launch_error=launch_error,
        host_method_passed=passed, host_exit=code, timeout=timeout, host_child_timeout_seconds=CHILD_SECONDS,
        host_elapsed_seconds=elapsed, input_snapshot_complete=complete, input_snapshot_entry_count=len(input_rows),
        expected_input_snapshot_entry_count=EXPECTED_INPUTS, inputs=input_rows,
        child_reads_private_snapshot=invoked, child_python_isolated_mode=True,
        declared_paired_case_count=10, declared_graph_case_count=20,
        known_initial_open_absence_skips_model_count=None if counts is None else counts[0],
        non_success_or_pending_model_count=None if counts is None else counts[1],
        uncertain_close_once_no_retry_model_count=None if counts is None else counts[2],
        native_client51_and_go52_actors_algorithm_host_model_tested=passed,
        native_proc_two_pass_and_client_image_pins_host_model_tested=passed,
        native_go_loader_entry_bootstrap_ctor_host_model_tested=passed,
        native_default_file_hash_and_metadata_gates_preserved_model_tested=passed,
        original_comm_open_error_path_flags_inventory_model_tested=passed,
        mandatory_actor_missing_and_late_errno2_refuse_model_tested=passed,
        post_fd_proc_image_and_close_enoent_not_skipped_model_tested=passed,
        neutral_actual_store_budget_bind_reader_ctor=True, exact_type_domains_isolated=passed,
        helper_functions_only_loaded=passed, old_test_class_or_method_loaded=False,
        old_passed_method_or_full_flow_replayed=False, original_failed_source_or_raw_modified=False,
        native_hash_or_actor_or_proc_success_stubbed=False, native_positive_grant_or_canonical_stubbed=False,
        linux_syscall_proc_fd_clock_modeled=True, python_cli_executable_identities_modeled=True,
        actual_pc_pinned_wpa_stock3_byte_inputs=True, actual_pc_zip_bytes_crc_checked=True,
        native_full_collect_status_snapshot_tested=False, native_bootstrap_run_tested=False,
        native_go_store_reservation_or_publication_tested=False, native_go_creation_or_restore_tested=False,
        actual_linux_proc_or_socket_tested=False, actual_physical_fd_or_ofd_closure_tested=False,
        actual_native_fork_exec_signal_wait_tested=False, actual_child_fd3_watchdog_tested=False,
        actual_device_performance_or_deadline_cause_proven=False, actual_p011_restore_verified=False,
        original_quota_expanded=False, original_active_cap_renewed=False, unknown_resource_cleared=False,
        state_production_receive_gate_enabled=False, p011_go_service_available=False,
        p011_ip_dhcp_tls_send_receive_available=False, device_accessed=False, rf_requested=False, phone_tested=False,
        private_key_or_user_identifier_public=False, raw_native_bytes_in_public_zip=False,
        full_syscall_wall_bound_verified=False, full_heap_bound_verified=False,
        stdout_fixed_marker_reviewed=stdout_reviewed, unittest_stderr_reviewed=stderr_reviewed,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        public_raw_included=passed, public_zip_member_count=4 if passed else 2)
    archive = publish(output, value, stdout, stderr, passed)
    print(json.dumps(dict(passed=passed, host_exit=code, timeout=timeout, elapsed_seconds=elapsed,
        result_zip=str(archive), zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())))
    return 0 if passed else 2 if verification_error or snapshot_error or launch_error else 1


if __name__ == '__main__': sys.exit(main())
