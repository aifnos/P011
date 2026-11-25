"""Fixed one-method PC Loader check; no lifecycle, RF, transfer or device use.

Source verification and a private immutable-by-convention byte snapshot precede
the selected child. The test executes actual frozen Loader/35 definitions over
modeled metadata/FD/clock, not actual Linux platform or executable validation.
WPA ELF bytes are archived privately; public ZIP members are fixed below.
"""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
CHECKER = 'host/client_deployment_loader_v31_check.py'
TEST = 'tests/test_client_deployment_loader_v31.py'
TEST_SHA = '8da1d6f4f1c7d8aeaca9aad39eb98038474d5f3f6bfffe26fad513bcf625a389'
TEST_BYTES = 19342
METHOD = 'DeploymentLoaderV31Tests.test_actual_loader35_retains_running_f_and_later_dhcp_codec_definitions'
PLAN = 'host/client_transfer_executor_v31_source_manifest.json'
PLAN_SHA = '35e6f1ba210f9fbd476f866c35e66b01c8d707dea017beae067c6f75d4b2fc9a'
PLAN_BYTES = 8081
WPA = 'native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant'
WPA_SHA = 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301'
WPA_BYTES = 1351192
PREFIX = b'HOST_LOADER_V31 '
CHILD_SECONDS = 60


def fixed(path, sha, size):
    raw = (BASE / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('source_changed')
    return raw


def verify():
    """Definition-source checks only; never import the test or runtime here."""
    inputs = {TEST: fixed(TEST, TEST_SHA, TEST_BYTES), PLAN: fixed(PLAN, PLAN_SHA, PLAN_BYTES)}
    plan = json.loads(inputs[PLAN])
    if type(plan) is not dict or set(plan) != {'previous_manifest_sha256', 'schema', 'sources'} or \
            plan['schema'] != 'client-transfer-executor-v31-host' or type(plan['sources']) is not list:
        raise ValueError('graph_changed')
    rows = plan['sources']
    if len(rows) != 35 or any(type(row) is not dict or set(row) != {'module', 'path', 'sha256', 'bytes'}
                              for row in rows) or len({row['module'] for row in rows}) != 35:
        raise ValueError('graph_changed')
    graph = None
    for row in rows:
        path = row['path']
        if type(path) is not str or not path or path.startswith(('/', '\\')) or '\\' in path or \
                ':' in path or any(part in ('', '.', '..') for part in path.split('/')) or \
                type(row['bytes']) is not int or not 1 <= row['bytes'] <= 2097152 or \
                type(row['sha256']) is not str or re.fullmatch('[0-9a-f]{64}', row['sha256']) is None:
            raise ValueError('source_changed')
        raw = fixed(path, row['sha256'], row['bytes'])
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        inputs[path] = raw
        if row['module'] == 'mta_client_executor':
            graph = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign) and
                     any(isinstance(target, ast.Name) and target.id == 'MODULES' for target in node.targets)]
    names = tuple(row['module'] for row in rows)
    if graph != [names]: raise ValueError('executor_graph_changed')
    tree = ast.parse(inputs[TEST].decode('utf-8'))
    methods = [cls.name + '.' + method.name for cls in tree.body if isinstance(cls, ast.ClassDef)
               for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')]
    if methods != [METHOD]: raise ValueError('method_changed')
    wanted = {'MANIFEST', 'MANIFEST_SHA', 'MANIFEST_BYTES', 'F_PIN', 'F_PATH',
              'WPA_PATH', 'WPA_PIN', 'WPA_BYTES', 'RUNNING_F_NAME'}
    constants = {target.id: ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                 for target in node.targets if isinstance(target, ast.Name) and target.id in wanted}
    f = next(row for row in rows if row['module'] == 'mta_client_executor')
    if constants != {'MANIFEST': PLAN, 'MANIFEST_SHA': PLAN_SHA, 'MANIFEST_BYTES': PLAN_BYTES,
        'F_PIN': f['sha256'], 'F_PATH': f['path'], 'WPA_PATH': WPA, 'WPA_PIN': WPA_SHA,
        'WPA_BYTES': WPA_BYTES, 'RUNNING_F_NAME': 'host_actual_deployment_loader_v31_f'}:
        raise ValueError('test_source_binding_changed')
    inputs[WPA] = fixed(WPA, WPA_SHA, WPA_BYTES)
    if not inputs[WPA].startswith(b'\x7fELF'): raise ValueError('elf_magic_changed')
    return rows, inputs


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('duplicate_stdout_key')
        result[key] = value
    return result


def no_constant(unused): raise ValueError('nonfinite_stdout')


def exact_tree(actual, expected):
    if type(actual) is not type(expected): return False
    if type(expected) is dict:
        return set(actual) == set(expected) and all(exact_tree(actual[key], value) for key, value in expected.items())
    if type(expected) is list:
        return len(actual) == len(expected) and all(exact_tree(left, right) for left, right in zip(actual, expected))
    return actual == expected


def review_stdout(raw, rows):
    """Only this exact canonical model declaration is eligible for publication."""
    if len(raw) > 16384: return None
    if raw.endswith(b'\r\n'): line = raw[:-2]
    elif raw.endswith(b'\n'): line = raw[:-1]
    else: return None
    if b'\r' in line or b'\n' in line or not line.startswith(PREFIX): return None
    try:
        observed = json.loads(line[len(PREFIX):].decode('ascii'),
            object_pairs_hook=strict_object, parse_constant=no_constant)
    except (ValueError, TypeError, UnicodeError): return None
    names = [row['module'] for row in rows]
    expected = {
        'scope': 'HOST actual frozen Loader/35 definitions; modeled file IO only',
        'source_manifest_sha256': PLAN_SHA, 'loaded_definitions': 35,
        'same_running_f_classes': True,
        'definitions_after_f': names[names.index('mta_client_executor') + 1:],
        'fictional_fd_open_count': 39, 'fictional_fd_once_close_count': 39,
        'modeled_platform_validation_count': 1,
        'clock': 'fixed HOST preparation 100; not elapsed-cost proof',
        'tmp': 'modeled exact /tmp->/var/tmp->/var/volatile/tmp',
        'wpa_elf': 'fixed local e069 bytes read/hashed; never executed',
        'python_elf': 'fictional bytes with matching hash; never executed',
        'actual_device_platform': False, 'rf': False, 'transfer': False,
        'restore': False, 'phone_compatible': False,
    }
    if not exact_tree(observed, expected) or \
            line != PREFIX + json.dumps(observed, sort_keys=True).encode('ascii'):
        return None
    return observed


def publish(output, value, stdout, stderr, passed):
    raw = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
    note = (
        'One new PC method only: actual frozen DeploymentLoader.load and 35 unique definitions. '
        'Original running F identity and later DHCP/receive imports are checked. '
        'All runtime file paths, root metadata, FD/EBADF and preparation clock are explicit HOST models. '
        'Locally pinned WPA ELF bytes are read/hashed, archived only in private-inputs, never executed. '
        'Python ELF bytes are fictional with matching hash. No authority constant or hash is replaced. '
        'Not real Linux/P011 platform, ELF execution, elapsed-bound, F lifecycle, Parent process, RF, '
        'transfer, restoration or Xiaomi acceptance. '
        'Public raw appears only after exact canonical HOST_LOADER_V31 model declaration and real Ran 1/OK '
        'stderr review plus child exit 0 and no timeout. Otherwise raw/input snapshots remain private.\n'
    ).encode('ascii')
    (output / 'result.json').write_bytes(raw); (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    members = ['result.json', 'README.txt'] + (['stdout.raw', 'stderr.raw'] if passed else [])
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', raw); bundle.writestr('README.txt', note)
        if passed:
            bundle.writestr('stdout.raw', stdout); bundle.writestr('stderr.raw', stderr)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != members or bundle.testzip() is not None or \
                bundle.read('result.json') != raw or bundle.read('README.txt') != note or \
                passed and (bundle.read('stdout.raw') != stdout or bundle.read('stderr.raw') != stderr):
            raise ValueError('archive_changed')
    return archive


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY: fixed one Loader method; no stage, path, network or device arguments')
        return 2
    output = BASE / 'results' / ('client-deployment-loader-v31-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    own = Path(__file__).read_bytes()
    rows, inputs, verification_error = [], {CHECKER: own}, None
    source_verified = False
    verify_started = time.monotonic()
    try:
        rows, verified_inputs = verify(); inputs.update(verified_inputs); source_verified = True
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, UnicodeError, StopIteration):
        verification_error = 'fixed_source_invalid'
    verification_seconds = time.monotonic() - verify_started
    snapshot = output / 'private-inputs'
    for path, raw in inputs.items():
        destination = snapshot / path
        destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(raw)
    stdout, stderr, code, timeout = b'', b'', None, False
    started, attempted, invoked, launch_error = time.monotonic(), False, False, None
    if source_verified:
        attempted = True
        try:
            # The copied test BASE resolves to this exact byte snapshot. No
            # sibling old test/domain is available or imported by this method.
            child = subprocess.run([sys.executable, '-B', str(snapshot / TEST), '-q', METHOD],
                cwd=str(snapshot), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=CHILD_SECONDS, check=False)
            stdout, stderr, code, invoked = child.stdout, child.stderr, child.returncode, True
        except subprocess.TimeoutExpired as error:
            stdout, stderr, code, timeout, invoked = error.stdout or b'', error.stderr or b'', None, True, True
        except OSError:
            launch_error = 'host_child_not_started'
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout); (output / 'stderr.raw').write_bytes(stderr)
    observed = review_stdout(stdout, rows) if source_verified else None
    unittest_reviewed = re.fullmatch(
        rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = invoked and source_verified and launch_error is None and code == 0 and not timeout and \
        observed is not None and unittest_reviewed
    value = dict(schema='client-deployment-loader-v31-host', selected_method=METHOD,
        selected_method_count=1, method_attempted=attempted, method_invoked=invoked, host_exit=code, timeout=timeout,
        host_child_timeout_seconds=CHILD_SECONDS, host_elapsed_seconds=elapsed,
        source_verification_elapsed_seconds=verification_seconds, verification_error=verification_error,
        launch_error=launch_error, host_method_passed=passed, source_integrity_verified=source_verified,
        python35_syntax_verified=source_verified, source_count=len(rows), sources=rows,
        source_manifest_sha256=PLAN_SHA, test_sha256=TEST_SHA, test_bytes=TEST_BYTES,
        checker_sha256=hashlib.sha256(own).hexdigest(), input_snapshot_complete=source_verified,
        input_snapshot_entry_count=len(inputs), child_reads_private_snapshot=invoked,
        native_wpa_sha256=WPA_SHA, native_wpa_bytes=WPA_BYTES,
        native_wpa_bytes_archived_private=WPA in inputs, native_wpa_bytes_in_public_zip=False,
        native_wpa_executed=False, python_elf_modeled=True, python_elf_executed=False,
        actual_deployment_loader_tested=passed, actual_unique_definitions_loaded=35 if passed else None,
        same_running_f_identity_verified=passed, later_dhcp_receive_definitions_loaded=passed,
        stdout_model_declaration_reviewed=observed is not None, unittest_stderr_reviewed=unittest_reviewed,
        loader_model_observation=observed, runtime_file_metadata_modeled=True,
        runtime_descriptors_modeled=True, preparation_clock_modeled=True,
        actual_linux_platform_tested=False, native_f_lifecycle_tested=False,
        actual_parent_process_tested=False, device_accessed=False, rf_requested=False,
        phone_tested=False, p011_send_available=False, p011_receive_available=False,
        actual_p011_restore_verified=False, actual_file_transfer_tested=False,
        full_syscall_wall_bound_verified=False, full_heap_bound_verified=False,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        public_raw_included=passed, public_zip_member_count=4 if passed else 2)
    archive = publish(output, value, stdout, stderr, passed)
    print(json.dumps(dict(selected_method=METHOD, passed=passed, host_exit=code, timeout=timeout,
        elapsed_seconds=elapsed, public_zip_member_count=4 if passed else 2,
        result_zip=str(archive), zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()), ensure_ascii=False))
    return 0 if passed else 2 if verification_error is not None or launch_error is not None else 1


if __name__ == '__main__': raise SystemExit(main())
