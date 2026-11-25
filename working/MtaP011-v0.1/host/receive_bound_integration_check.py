"""Affected bound receive integration on HOST WSL; immutable source snapshots."""
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
TEST = 'tests/test_receive_bound_integration.py'
STORAGE = 'candidate/receive-directory-fd-v1/runtime/mta_storage.py'
TARGETS = ('candidate/receive-directory-fd-v1/runtime/mta_transport.py',)
SOURCES = (TEST, 'host/receive_bound_integration_check.py',
    'HOST_MTA_RECEIVE_BOUND_INTEGRATION_CHECK.cmd', 'tests/test_sender_pump.py',
    'runtime/mta_send_preparation.py', 'runtime/mta_sender_pump.py',
    'runtime/mta_protocol.py', 'runtime/p011_json.py',
    'candidate/file-utf8-v67/runtime/mta_files.py',
    'integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py', STORAGE) + TARGETS


def main():
    if len(sys.argv) != 1:
        return 2
    originals = {name: (BASE / name).read_bytes() for name in SOURCES}
    for name in TARGETS:
        ast.parse(originals[name].decode('utf-8'), feature_version=(3, 5))
    out = BASE / 'results' / ('receive-bound-integration-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    private = out / 'private-inputs'
    for name, raw in originals.items():
        path = private / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        if path.read_bytes() != raw:
            raise ValueError('snapshot_changed')
    windows_path = str(private / TEST)
    if windows_path[:3].lower() != 'd:\\':
        raise ValueError('fixed_workspace_required')
    script = '/mnt/d/' + windows_path[3:].replace('\\', '/')
    argv = ['wsl.exe', '-d', 'kali-linux', '--exec', '/usr/bin/python3', '-I', '-B', script, '-q']
    timed_out = False
    try:
        child = subprocess.run(argv, cwd=private, capture_output=True, timeout=45)
        stdout, stderr, code = child.stdout, child.stderr, child.returncode
    except subprocess.TimeoutExpired as failure:
        stdout, stderr, code = failure.stdout or b'', failure.stderr or b'', None
        timed_out = True
    (out / 'stdout.raw').write_bytes(stdout)
    (out / 'stderr.raw').write_bytes(stderr)
    parsed = None
    try:
        lines = stdout.decode('ascii').splitlines()
        if len(lines) == 1 and lines[0].startswith('RESULT='):
            parsed = json.loads(lines[0][7:])
    except (ValueError, UnicodeError):
        pass
    unchanged = all((BASE / name).read_bytes() == raw and (private / name).read_bytes() == raw
        for name, raw in originals.items())
    true_fields = ('passed', 'actual_prepared_send', 'actual_sender_pump', 'actual_receiver_transport',
        'consent_blocked_download_verified', 'actual_linux_directory_fd', 'one_original_archive_handle',
        'original_binding_borrowed', 'binding_closure_verified', 'chinese_file_commit_verified',
        'filecenter_read_verified', 'local_commit_verified', 'peer_ack_verified',
        'socket_file_cleanup_verified', 'host_loopback_admission_fixture', 'host_loopback_owner')
    false_fields = ('device_tested', 'phone_tested', 'rf_requested', 'full_restore_verified')
    counts = dict(new_methods=1, old_methods=0, actual_tls_connections=2)
    shape = (type(parsed) is dict and set(parsed) == set(true_fields + false_fields) | set(counts) and
        all(parsed[name] is True for name in true_fields) and all(parsed[name] is False for name in false_fields) and
        all(type(parsed[name]) is int and parsed[name] == value for name, value in counts.items()))
    derived_stderr = stderr.replace(b'\r\n', b'\n')
    known_startup_warning = b"wsl: Failed to start the systemd user session for 'admin'. See journalctl for more details.\n"
    startup_warning = derived_stderr.startswith(known_startup_warning)
    if startup_warning:
        derived_stderr = derived_stderr[len(known_startup_warning):]
    unittest_raw = re.fullmatch(br'-+\nRan 1 test in [0-9]+\.[0-9]+s\n\nOK\n', derived_stderr) is not None
    passed = code == 0 and not timed_out and unchanged and shape and unittest_raw
    report = dict(passed=passed, child_exit=code, timeout=timed_out, child_invocations=1,
        new_methods=1, old_methods=0, actual_p011=False, phone=False, production_admission=False,
        source_snapshots_equal=unchanged, target_python35_ast_sources=len(TARGETS), integration=parsed,
        wsl_user_session_warning=startup_warning,
        inputs=[dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            for name, raw in originals.items()],
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest())
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'One affected new HOST Linux PreparedSend/SenderPump/TLS receive integration. '
        b'Actual directory FDs and one retained w+b archive handle for download and ZIP parsing; '
        b'Chinese commit/FileCenter/ACK and closure. Existing HOST loopback socket owner and '
        b'constructor allowance are explicit fixtures. Not State/F, P011, RF, phone or physical restore. '
        b'Old test methods are not run. Private input snapshots, raw and generated keys are excluded.\n')
    members = {'result.json': result, 'README.txt': readme}
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
        result_dir=str(out), result_zip=str(archive),
        zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
