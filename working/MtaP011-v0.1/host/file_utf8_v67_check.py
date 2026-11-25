"""Fixed PC-only UTF-8 file boundary check; never uses ADB or changes radios.

One isolated child executes six new methods against private source copies.
ASCII/POSIX path handling is simulated around real HOST temporary files;
Windows FileStore readback is not the P011 directory-FD branch. No old test
method, service entry, network, deployment, admission or recovery is run.
Failure raw are private; only a strict success marker permits public raw.
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
CHECKER = 'host/file_utf8_v67_check.py'
TEST = 'tests/test_file_utf8_v67.py'
FIXED = (
    ('candidate/file-utf8-v67/runtime/mta_storage.py', 15161, '9bcc905c8cc44400a83ad5d4f0a2fc9dafb8d28c36ba40f76e7ce9cdc3857afb'),
    ('candidate/file-utf8-v67/runtime/mta_files.py', 10987, 'c6316be40cf34f017d1d2160f48989a55edfa0a60a2abe6a2ff6b656773f752b'),
    ('runtime/mta_protocol.py', 17958, '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('runtime/p011_json.py', 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py', 9114, 'd9fa92a795729d88f6fac27705a2883adba8aac72423b4ebcd9220ffb78ddb51'),
    (TEST, 24076, '14f99e713c4b7ab0ba23e35ee5cf927ac0b1eb82a018ec92cd1cf49938be851e'),
)
ORIGINALS = (
    ('runtime/mta_storage.py', 14335, '3c5c5f65ef0c8eb9a0256a99f931faff40558484bb908e89acee1c1c0aa3b4d6'),
    ('runtime/mta_files.py', 10267, 'c37a00be58487abee32abf7ded7ed857e059883aee680e049e6372d3d06681ae'),
)
MARKER = b'HOST67_FILE_UTF8 new_methods=6 old_methods=0 simulated_ascii=true device=false phone=false\n'
CHILD_SECONDS = 60


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify():
    inputs = {CHECKER: Path(__file__).read_bytes()}
    for path, size, digest in FIXED + ORIGINALS:
        raw = (BASE / path).read_bytes()
        if len(raw) != size or sha(raw) != digest:
            raise ValueError('fixed_input_changed')
        if (path, size, digest) in FIXED:
            inputs[path] = raw
        if path != TEST:
            ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    parsed = ast.parse(inputs[TEST].decode('utf-8'))
    methods = [node.name + '.' + child.name for node in parsed.body
        if isinstance(node, ast.ClassDef) for child in node.body
        if isinstance(child, ast.FunctionDef) and child.name.startswith('test_')]
    if len(methods) != 6 or len(set(methods)) != 6:
        raise ValueError('new_method_count_changed')
    if len(inputs) != 7:
        raise ValueError('input_count_changed')
    return inputs, methods


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY fixed UTF8 check; no device/network/path arguments')
        return 2
    output = BASE / 'results' / ('file-utf8-v67-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    inputs, methods, rows = {}, [], []
    verified, error = False, None
    try:
        inputs, methods = verify()
        private = output / 'private-inputs' / 'project' / 'working' / 'MtaP011-v0.1'
        for path, raw in sorted(inputs.items()):
            destination = private / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            if destination.read_bytes() != raw:
                raise ValueError('private_copy_changed')
            rows.append(dict(path=path, bytes=len(raw), sha256=sha(raw)))
        verified = True
    except (OSError, ValueError, UnicodeError, SyntaxError):
        error = 'source_or_snapshot_invalid'
    stdout, stderr, code, timeout, invoked = b'', b'', None, False, False
    started = time.monotonic()
    if verified:
        env = dict(os.environ)
        env.pop('PYTHONPATH', None)
        env.pop('PYTHONSTARTUP', None)
        try:
            child = subprocess.run([sys.executable, '-I', '-B', str(private / TEST), '-q'],
                cwd=str(private), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=CHILD_SECONDS, check=False)
            stdout, stderr, code, invoked = child.stdout, child.stderr, child.returncode, True
        except subprocess.TimeoutExpired as failure:
            stdout, stderr, timeout, invoked = failure.stdout or b'', failure.stderr or b'', True, True
        except OSError:
            error = 'child_not_started'
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    originals_preserved = False
    try:
        observed_originals = [(path, (BASE / path).read_bytes(), size, digest)
            for path, size, digest in ORIGINALS]
        originals_preserved = all(len(raw) == size and sha(raw) == digest
            for path, raw, size, digest in observed_originals)
    except OSError:
        pass
    stdout_ok = stdout in (MARKER, MARKER.replace(b'\n', b'\r\n'))
    stderr_ok = re.fullmatch(rb'-{70}\r?\nRan 6 tests in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = verified and invoked and code == 0 and not timeout and stdout_ok and stderr_ok and originals_preserved
    value = dict(schema='file-utf8-v67-host', passed=passed, source_verified=verified,
        source_snapshot_count=len(rows), inputs=rows, new_methods=methods,
        child_invocations=int(invoked), old_test_methods_invoked=0,
        host_exit=code, timeout=timeout, host_elapsed_seconds=elapsed,
        child_timeout_seconds=CHILD_SECONDS, verification_error=error,
        python35_target_syntax_verified=verified, real_host_temporary_files_used=passed,
        simulated_ascii_path_boundary=True, existing_toolbox_host_readback_tested=passed,
        actual_posix_ascii_runtime_tested=False, actual_p011_directory_fd_branch_tested=False,
        p011_tested=False, phone_tested=False, device_accessed=False, rf_requested=False,
        network_service_started=False, receive_admission_enabled=False,
        p011_send_receive_available=False, actual_network_restore_verified=False,
        original_runtime_preserved=originals_preserved,
        original_runtime_modified=False if originals_preserved else None,
        source_only_candidate_not_deployed=True,
        stdout_fixed_marker_reviewed=stdout_ok, stderr_unittest_reviewed=stderr_ok,
        stdout_bytes=len(stdout), stderr_bytes=len(stderr),
        stdout_sha256=sha(stdout), stderr_sha256=sha(stderr),
        public_raw_included=passed, public_zip_member_count=4 if passed else 2)
    result = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (
        'PC-only: six new UTF-8 methods, one isolated -I -B child, no retries. '
        'Private fixed source copies; original runtime files remain unchanged. '
        'ASCII/POSIX path ABI is simulated around real HOST temporary files. '
        'Existing FileStore HOST readback does not test P011 directory-FD behavior. '
        'No old test method, service, deployment, admission, ADB, radio or recovery runs. '
        'Candidate is not deployed; P011 and phone transfer remain unverified. '
        'Only strict marker plus Ran6/OK, exit0 and no timeout permit public raw. '
        'On failure stdout/stderr remain private. Previous failures are not replaced.\n').encode('ascii')
    (output / 'result.json').write_bytes(result)
    (output / 'README.txt').write_bytes(readme)
    members = {'result.json': result, 'README.txt': readme}
    if passed:
        members.update({'stdout.raw': stdout, 'stderr.raw': stderr})
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in members.items():
            bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != list(members) or bundle.testzip() is not None:
            raise ValueError('zip_inventory_changed')
        for name, raw in members.items():
            info = bundle.getinfo(name)
            if (bundle.read(name) != raw or info.file_size != len(raw) or
                    info.CRC != (zlib.crc32(raw) & 0xffffffff) or (output / name).read_bytes() != raw):
                raise ValueError('zip_member_changed')
    print(json.dumps(dict(passed=passed, host_exit=code, timeout=timeout,
        elapsed_seconds=elapsed, result_zip=str(archive), zip_sha256=sha(archive.read_bytes()))))
    return 0 if passed else 2 if error else 1


if __name__ == '__main__':
    sys.exit(main())
