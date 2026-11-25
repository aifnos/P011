"""PC-only affected service-owner check; never a device/MTA trial.

One isolated child runs only the new owner test. Boot FS/ABI and native helper
preflight/probes are explicit HOST fixtures; actual State, Registry, loopback
HTTP sockets and threads run. Windows socket metadata/EBADF is a named model;
file descriptors use actual OS evidence. No Handoff, RF or receive admission.
Input raw bytes are copied to a unique private snapshot; no old tests run.
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
CHECKER = 'host/client_service_owner_v70_check.py'
OWNER = 'candidate/client-service-owner-v70/runtime/mta_client_service_owner.py'
BOOT = 'candidate/client-receive-factory-v69-r3/runtime/mta_client_receive_boot.py'
TEST = 'tests/test_client_service_owner_v70.py'
# Exact new SOURCE pins; only this affected service-owner test may run.
BOOT_PIN = '1c3d05c3bf588aa2b6438e6d940fd5e36e467860c1b183305566a18ed69695aa'
OWNER_PIN = 'f70046e538db7427dd0af374067f684eb41bafb2f70999a2c3deaf87e8705466'
TEST_PIN = '38d05c08403a6966a4b18b03eed8f05628e8073ca47c1b19e69dd4e64b23f599'
NATIVE_PINS = (
    ('out/native/mta-bluez-helper', 65832, '179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363'),
    ('out/native/mta-network-helper', 47464, 'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6'),
)
MARKER = b'HOST70_SERVICE_OWNER new_methods=1 old_methods=0 boot_model=true loopback=true device=false phone=false\n'
METHOD = 'ServiceOwner70Test.test_actual_service_start_http_and_close'
SPECIAL = {
    'mta_client_executor': 'candidate/client-integrated-v37/runtime/mta_client_executor.py',
    'mta_client_control_frame': 'candidate/client-integrated-v37/runtime/mta_client_control_frame.py',
    'mta_client_connect_handoff': 'candidate/client-connect-v13/runtime/mta_client_connect_handoff.py',
    'mta_client_tmp_alias': 'candidate/client-tmp-alias-v11/runtime/mta_client_tmp_alias.py',
    'mta_service': 'candidate/client-state-integration-v32/runtime/mta_service.py',
    'mta_client_receive_factory': 'candidate/client-receive-factory-v69-r3/runtime/mta_client_receive_factory.py',
    'mta_client_state_bridge': 'candidate/client-receive-factory-v69/runtime/mta_client_state_bridge.py',
}
ORIGINAL_BRIDGE = ('candidate/client-state-bridge-v37/runtime/mta_client_state_bridge.py',
    19534, '0f7ae69c36a65bb8b4c0fc5f63300efe4c71c8f2af4c1ed2eddeb286c98c0d0c')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def literal(node, values):
    if isinstance(node, ast.Name):
        return values[node.id]
    if isinstance(node, ast.Tuple):
        return tuple(literal(part, values) for part in node.elts)
    return ast.literal_eval(node)


def verified_inputs():
    boot = (BASE / BOOT).read_bytes()
    if type(BOOT_PIN) is not str or sha(boot) != BOOT_PIN:
        raise ValueError('unfrozen_boot')
    tree = ast.parse(boot.decode('utf-8'), feature_version=(3, 5))
    constants = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in ('F37_SHA', 'SOURCE_PINS'):
                constants[name] = literal(node.value, constants)
    pins = constants.get('SOURCE_PINS')
    if type(pins) is not tuple or len(pins) != 22 or len({row[0] for row in pins}) != 22:
        raise ValueError('fixed_graph_changed')
    inputs = {BOOT: boot, CHECKER: Path(__file__).read_bytes()}
    originals = [ORIGINAL_BRIDGE]
    for name, size, digest in pins:
        if type(name) is not str or re.fullmatch('[a-z][a-z0-9_]{0,63}', name) is None or \
                type(size) is not int or type(digest) is not str or re.fullmatch('[0-9a-f]{64}', digest) is None:
            raise ValueError('fixed_shape_changed')
        path = SPECIAL.get(name, 'runtime/' + name + '.py')
        raw = (BASE / path).read_bytes()
        if len(raw) != size or sha(raw) != digest:
            raise ValueError('fixed_source_changed')
        ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        inputs[path] = raw
        if name not in ('mta_client_receive_factory', 'mta_client_state_bridge'):
            originals.append((path, size, digest))
    owner = (BASE / OWNER).read_bytes()
    if type(OWNER_PIN) is not str or sha(owner) != OWNER_PIN:
        raise ValueError('unfrozen_owner')
    ast.parse(owner.decode('utf-8'), feature_version=(3, 5))
    inputs[OWNER] = owner
    for path, size, digest in NATIVE_PINS:
        raw = (BASE / path).read_bytes()
        if len(raw) != size or sha(raw) != digest:
            raise ValueError('native_source_changed')
        inputs[path] = raw
        originals.append((path, size, digest))
    test = (BASE / TEST).read_bytes()
    if type(TEST_PIN) is not str or sha(test) != TEST_PIN:
        raise ValueError('unfrozen_test')
    methods = [node.name + '.' + part.name for node in ast.parse(test.decode('utf-8')).body
        if isinstance(node, ast.ClassDef) for part in node.body
        if isinstance(part, ast.FunctionDef) and part.name.startswith('test_')]
    if methods != [METHOD]:
        raise ValueError('new_method_changed')
    inputs[TEST] = test
    for path, size, digest in originals:
        raw = (BASE / path).read_bytes()
        if len(raw) != size or sha(raw) != digest:
            raise ValueError('original_source_changed')
    if len(inputs) != 28:
        raise ValueError('input_count_changed')
    return inputs, originals


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY no device, network, path or method arguments')
        return 2
    output = BASE / 'results' / ('client-service-owner-v70-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    inputs, originals, rows = {}, [], []
    verified, error = False, None
    try:
        inputs, originals = verified_inputs()
        private = output / 'private-inputs' / 'project' / 'working' / 'MtaP011-v0.1'
        for path, raw in sorted(inputs.items()):
            target = private / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            if target.read_bytes() != raw: raise ValueError('snapshot_changed')
            rows.append(dict(path=path, bytes=len(raw), sha256=sha(raw)))
        verified = True
    except (OSError, ValueError, KeyError, UnicodeError, SyntaxError):
        error = 'source_or_snapshot_invalid'
    stdout, stderr, code, invoked, timeout = b'', b'', None, False, False
    started = time.monotonic()
    if verified:
        env = dict(os.environ)
        env.pop('PYTHONPATH', None)
        env.pop('PYTHONSTARTUP', None)
        try:
            child = subprocess.run([sys.executable, '-I', '-B', str(private / TEST), '-q'],
                cwd=str(private), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=60, check=False)
            stdout, stderr, code, invoked = child.stdout, child.stderr, child.returncode, True
        except subprocess.TimeoutExpired as failure:
            stdout, stderr, timeout, invoked = failure.stdout or b'', failure.stderr or b'', True, True
        except OSError:
            error = 'child_not_started'
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    originals_preserved = verified
    for path, size, digest in originals:
        try:
            raw = (BASE / path).read_bytes()
            originals_preserved = originals_preserved and len(raw) == size and sha(raw) == digest
        except OSError:
            originals_preserved = False
    marker_ok = stdout in (MARKER, MARKER.replace(b'\n', b'\r\n'))
    stderr_ok = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    methods_observed = (1 if re.search(rb'\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n', stderr)
                        else None if invoked else 0)
    passed = verified and invoked and code == 0 and not timeout and marker_ok and stderr_ok and originals_preserved
    value = dict(schema='client-service-owner-v70-host', source_revision='v70', passed=passed,
        source_verified=verified, source_snapshot_count=len(rows), inputs=rows,
        new_method=METHOD, new_methods_invoked=methods_observed, old_methods_invoked=0,
        new_fixture_count=10,
        child_invocations=int(invoked), host_exit=code, timeout=timeout, host_elapsed_seconds=elapsed,
        verification_error=error, original_sources_preserved=originals_preserved,
        stdout_bytes=len(stdout), stdout_sha256=sha(stdout), stderr_bytes=len(stderr), stderr_sha256=sha(stderr),
        fixed_marker_verified=marker_ok, unittest_summary_verified=stderr_ok,
        boot_filesystem_model=True, capability_probes_model=True,
        socket_metadata_model=True, socket_ebadf_model=True, native_helpers_executed=False,
        actual_host_loopback_tested=True if passed else None,
        actual_p011_abi_tested=False, actual_filesystem_publication_tested=False,
        actual_factory_handoff_tested=False, deployment_loader_invoked=False,
        state_constructed=True if passed else None, service_started=True if passed else None,
        service_resource_close_tested=True if passed else None, parent_started=False,
        device_accessed=False, rf_requested=False, send_available=False, receive_available=False,
        phone_tested=False, full_native_restore_verified=False, candidate_deployed=False)
    result = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (
        'PC-only: one new service-owner method with actual HOST State/Registry/loopback HTTP/threads. '
        'Boot FS/ABI and fixed native helper preflight/probes are explicit HOST fixtures, not ARM/native evidence. '
        'Windows socket metadata and EBADF are named models; actual TCP, original socket close/fileno '
        'and threads are observed. File asset FD reads/close/EBADF use the actual host OS. '
        'Original source bytes are pinned and copied into a unique private snapshot. '
        'No Handoff/Parent/DeploymentLoader, factory positive, device, RF or phone flow starts. '
        'No old test method is imported or replayed. The production candidate is not deployed. '
        'HOST service closure does not grant receive admission or verify physical publication/network restoration. '
        'Only strict fixed stdout plus Ran1/OK, exit0 and no timeout permit public raw. '
        'Failures retain raw privately and do not replace any historical results.\n').encode('ascii')
    (output / 'result.json').write_bytes(result)
    (output / 'README.txt').write_bytes(readme)
    members = {'result.json': result, 'README.txt': readme}
    if passed: members.update({'stdout.raw': stdout, 'stderr.raw': stderr})
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in members.items(): bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != list(members) or bundle.testzip() is not None: raise ValueError('zip_inventory')
        for name, raw in members.items():
            entry = bundle.getinfo(name)
            if bundle.read(name) != raw or entry.file_size != len(raw) or entry.CRC != zlib.crc32(raw) & 0xffffffff:
                raise ValueError('zip_member')
    print(json.dumps(dict(passed=passed, host_exit=code, timeout=timeout,
        elapsed_seconds=elapsed, result_zip=str(archive), zip_sha256=sha(archive.read_bytes()))))
    return 0 if passed else 2 if error else 1


if __name__ == '__main__':
    sys.exit(main())
