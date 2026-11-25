"""One new Owner close method on HOST Linux; no device or old tests."""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
TEST = 'tests/test_receive_http_directory_close.py'
OWNER = 'candidate/receive-http-directory-close-v3/runtime/mta_client_service_owner.py'
TEST_PIN = (24904, '42903edecbdcaa609804fc99296c296911a5863c3c8149cfd338f343cdac35ad')
OWNER_PIN = (42663, '6aba9a6f60109b7fb3568e7b85e58889e76dbff99da9f633604ad408e94c029c')
METHOD = 'ReceiveHttpDirectoryCloseTest.test_http_quiescence_before_directory_release'
SOURCES = (TEST, OWNER, 'candidate/receive-directory-fd-v1/runtime/mta_storage.py',
    'runtime/mta_protocol.py', 'runtime/p011_json.py',
    'host/receive_http_directory_close_check.py', 'HOST_MTA_RECEIVE_HTTP_DIRECTORY_CLOSE_CHECK.cmd')
FIXED = (
    (SOURCES[2], 55562, 'ea3d3df1177019125c9b3124b8ebaf33196dd1013db95ac24580e1fe1a96c8d1'),
    (SOURCES[3], 17958, '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    (SOURCES[4], 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
)
MARKER = (b'HOST_RECEIVE_HTTP_DIRECTORY_CLOSE new_methods=1 old_methods=0 domains=6 fixtures=8 '
    b'linux_kernel=true state_model=true device=false phone=false\n')


def _wsl_path(path):
    value = str(path)
    if len(value) < 3 or value[1:3] != ':\\' or value[0].lower() != 'd':
        raise ValueError('fixed_workspace_required')
    return '/mnt/d/' + value[3:].replace('\\', '/')


def main():
    if len(sys.argv) != 1:
        return 2
    if sys.version_info[:2] != (3, 12) or TEST_PIN is None or OWNER_PIN is None:
        raise ValueError('fixed_HOST_python312_and_SOURCE_pins_required')
    originals = {name: (BASE / name).read_bytes() for name in SOURCES}
    fixed = ((TEST, TEST_PIN[0], TEST_PIN[1]), (OWNER, OWNER_PIN[0], OWNER_PIN[1])) + FIXED
    for name, count, digest in fixed:
        raw = originals[name]
        if len(raw) != count or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('fixed_input_changed')
    # Exactly the changed Owner. No old Storage/Transport/Protocol AST replay.
    ast.parse(originals[OWNER].decode('utf-8'), filename=OWNER, feature_version=(3, 5))
    out = BASE / 'results' / ('receive-http-directory-close-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    private = out / 'private-inputs'
    for name, raw in originals.items():
        target = private / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        if target.read_bytes() != raw:
            raise ValueError('snapshot_readback')
    timed_out = False
    try:
        child = subprocess.run(['wsl.exe', '-d', 'kali-linux', '--exec', '/usr/bin/python3',
            '-I', '-B', _wsl_path(private / TEST), METHOD], cwd=private,
            capture_output=True, timeout=45)
        stdout, stderr, code = child.stdout, child.stderr, child.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code = error.stdout or b'', error.stderr or b'', None
        timed_out = True
    (out / 'stdout.raw').write_bytes(stdout)
    (out / 'stderr.raw').write_bytes(stderr)
    unchanged = all((BASE / name).read_bytes() == raw and (private / name).read_bytes() == raw
        for name, raw in originals.items())
    derived = stderr.replace(b'\r\n', b'\n')
    warning = b"wsl: Failed to start the systemd user session for 'admin'. See journalctl for more details.\n"
    startup_warning = derived.startswith(warning)
    if startup_warning:
        derived = derived[len(warning):]
    summary_ok = re.fullmatch(br'\.\n-{70}\nRan 1 test in [0-9]+\.[0-9]+s\n\nOK\n', derived) is not None
    passed = (code == 0 and not timed_out and unchanged and
        stdout in (MARKER, MARKER.replace(b'\n', b'\r\n')) and summary_ok)
    report = dict(schema='receive-http-directory-close-host-v3', passed=passed,
        child_exit=code, timeout=timed_out, child_invocations=1, new_methods=1, old_methods=0,
        completed_domains=6 if passed else None, completed_fixtures=8 if passed else None,
        source_snapshots_equal=unchanged, snapshot_count=len(originals),
        target_python35_ast_sources=1, target_ast_path=OWNER,
        wsl_user_session_warning=startup_warning, actual_owner_close_tested=passed,
        actual_linux_directory_FD_tested=passed, actual_thread_socket_close_tested=passed,
        http_handler_model=True, state_model=True, boot_model=True, deadline_fault_model=True,
        server_started=False, factory_published=False, parent_started=False,
        native_tested=False, device_accessed=False, rf_requested=False, phone_tested=False,
        receive_available=False, production_admission=False, restoration_verified=False,
        private_raw_included=False,
        inputs=[dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            for name, raw in originals.items()],
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest())
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'One new affected Owner close/directory-release method: six domains/eight fixtures. '
        b'Actual HOST Linux temporary directory FDs, socketpair and Thread/Event/join; complete verified Owner '
        b'definitions and unchanged Storage definitions. Boot, State and HTTP-handler ancestors are explicit '
        b'models; one cleanup-deadline clock fault is explicit instrumentation. No old test method, actual '
        b'HTTP service startup, Factory, Parent, Native, RF, P011, phone, admission or restoration. '
        b'Only changed Owner Python 3.5 AST; original raw and inputs stay private.\n')
    members = {'result.json': result, 'README.txt': note}
    for name, raw in members.items():
        (out / name).write_bytes(raw)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in members.items():
            bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != list(members) or bundle.testzip() is not None or \
                any(bundle.read(name) != raw for name, raw in members.items()):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=passed, child_exit=code, timeout=timed_out,
        result_dir=str(out), result_zip=str(archive), zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
