"""One pinned PC IPC method; four definitions, never the 35-source lifecycle.

Run only the private input snapshot with isolated Python. Preserve first raw
streams locally. A recognized IPC model result is not RF/TLS/Parent launch,
restoration, a P011 deployment or phone interoperability evidence.
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
import zlib

BASE = Path(__file__).resolve().parents[1]
TEST = 'tests/test_client_terminal_v34.py'
TEST_SHA = '24be86b074b1f53fca8b0b866f7ce364d7d353556d8a0c9325a08e9f9a027975'
TEST_BYTES = 8846
METHOD = 'ClientTerminalV34Tests.test_native_codec_and_parent_pre_prompt_terminals_are_stop_only'
SOURCES = (
    ('p011_json', 'runtime/p011_json.py',
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88', 8061),
    ('mta_protocol', 'runtime/mta_protocol.py',
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57', 17958),
    ('mta_client_control_frame', 'candidate/client-terminal-v34/runtime/mta_client_control_frame.py',
     'd1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278', 20942),
    ('mta_client_executor', 'candidate/client-terminal-v34/runtime/mta_client_executor.py',
     'ea2807f60f531549854210f4a8b4f8ef066614049ba4c55aa55fedda4c2ba4bc', 98925),
)
EXPECTED = {'allowed': 3, 'duplicates_rejected': 3, 'encoded_negative': 33,
    'decoded_negative': 33, 'parent_negative': 44,
    'confirmation_timeout_requires_prompt': True, 'parent_spawn_executed': False,
    'rf_tested': False, 'restore_verified': False, 'phone_tested': False}


def fixed(path, pin, size):
    raw = (BASE / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('fixed_input_changed')
    return raw


def verify():
    inputs = {TEST: fixed(TEST, TEST_SHA, TEST_BYTES)}
    for module, path, pin, size in SOURCES:
        raw = fixed(path, pin, size)
        inputs[path] = raw
        tree = ast.parse(raw.decode('utf-8'), filename=path, feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('target_assert_changed')
    tree = ast.parse(inputs[TEST].decode('utf-8'), filename=TEST)
    methods = [cls.name + '.' + method.name for cls in tree.body if isinstance(cls, ast.ClassDef)
        for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')]
    if methods != [METHOD]: raise ValueError('method_scope_changed')
    constants = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == 'INPUTS' for target in node.targets)]
    if constants != [tuple(row[:3] for row in SOURCES)]:
        raise ValueError('definition_scope_changed')
    return inputs


def standard_output(stdout, stderr):
    marker = ('HOST_PRE_PROMPT_TERMINAL_V34_ONLY ' + json.dumps(EXPECTED, sort_keys=True)).encode('ascii')
    return stdout in (marker + b'\n', marker + b'\r\n') and re.fullmatch(
        rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY: fixed one-method check; no stage, path or device arguments')
        return 2
    try: inputs = verify()
    except (OSError, ValueError, TypeError, SyntaxError, UnicodeError):
        print('PC_ONLY_FAIL: fixed input invalid; no method executed')
        return 2
    own = Path(__file__).read_bytes()
    inputs['host/client_terminal_v34_check.py'] = own
    output = BASE / 'results' / ('client-terminal-v34-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    snapshot = output / 'private-inputs'
    for path, raw in inputs.items():
        destination = snapshot / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        if destination.read_bytes() != raw: raise ValueError('snapshot_changed')
    started, timeout = time.monotonic(), False
    try:
        child = subprocess.run([sys.executable, '-I', '-B', str(snapshot / TEST), '-q', METHOD],
            cwd=str(snapshot), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30, check=False)
        stdout, stderr, code = child.stdout, child.stderr, child.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code, timeout = error.stdout or b'', error.stderr or b'', None, True
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    if (output / 'stdout.raw').read_bytes() != stdout or (output / 'stderr.raw').read_bytes() != stderr:
        raise ValueError('external_raw_changed')
    passed = code == 0 and not timeout and standard_output(stdout, stderr)
    value = dict(schema='client-terminal-v34-narrow-host', selected_method=METHOD,
        selected_method_count=1, test_sha256=TEST_SHA, test_bytes=TEST_BYTES,
        source_count=4, executed_definition_count=4,
        sources=[dict(module=module, path=path, sha256=pin, bytes=size)
                 for module, path, pin, size in SOURCES],
        source_integrity_verified=True, python35_source_syntax_verified=True,
        fixed_private_snapshot_executed=True, isolated_python=True,
        child_exit=code, timeout=timeout, child_elapsed_seconds=elapsed,
        host_method_passed=passed, host_typed_ipc_tested=passed,
        recognized_model_proof=dict(EXPECTED) if passed else None,
        modeled_connect_sent_and_binding=True, synthetic_clock=True,
        full_35_source_lifecycle_tested=False, native_f_lifecycle_tested=False,
        deployment_loader_tested=False, actual_parent_fifo_tested=False,
        parent_spawn_executed=False, device_accessed=False, rf_requested=False,
        actual_tls_tested=False, actual_file_transfer_tested=False,
        restoration_verified=False, phone_tested=False,
        send_available=False, receive_available=False,
        full_syscall_wall_bound_verified=False, full_heap_bound_verified=False,
        checker_sha256=hashlib.sha256(own).hexdigest(),
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        stdout_bytes=len(stdout), stderr_bytes=len(stderr), public_raw_included=passed)
    encoded = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
    note = b'PC narrow typed IPC only: four pinned definitions, canonical encode/decode and actual Parent parser over modeled CONNECT/binding/clock. No 35-source F lifecycle, RF/TLS, Parent spawn, physical FIFO, file transfer, restoration, P011 deployment or Xiaomi interoperability proof. First failed raw and snapshots remain private.\n'
    (output / 'result.json').write_bytes(encoded)
    (output / 'README.txt').write_bytes(note)
    contents = [('result.json', encoded), ('README.txt', note)]
    if passed: contents += [('stdout.raw', stdout), ('stderr.raw', stderr)]
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in contents: bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != [name for name, raw in contents] or bundle.testzip() is not None:
            raise ValueError('archive_members_changed')
        for name, raw in contents:
            info = bundle.getinfo(name)
            if info.file_size != len(raw) or info.CRC != zlib.crc32(raw) & 0xffffffff or bundle.read(name) != raw:
                raise ValueError('archive_bytes_changed')
            if (output / name).read_bytes() != raw: raise ValueError('external_member_changed')
    print(json.dumps(dict(passed=passed, child_exit=code, timeout=timeout,
        elapsed_seconds=elapsed, result_zip=str(archive),
        zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()), ensure_ascii=False))
    return 0 if passed else 1


if __name__ == '__main__': raise SystemExit(main())
