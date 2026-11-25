"""One new F authentication-clock method, ancestry models, no device/WSL."""
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
TEST = 'tests/test_receive_directory_auth_clock.py'
TEST_PIN = (10289, 'ff1fddbd26d966278aaa466034949d71546f555bfd6f238ae770c469c7aab7a1')
F = 'candidate/receive-directory-auth-clock-v2/runtime/mta_client_executor.py'
F_PIN = (114074, '01dfd6295f2ac06464e7d7b0de1d99aa1ec97bef25f95222efa346609f25ecfb')
METHOD = 'ReceiveDirectoryAuthClockTest.test_authenticate_uses_original_directory_clock'
SOURCES = (TEST, F, 'runtime/p011_json.py', 'runtime/mta_protocol.py',
    'candidate/client-integrated-v37/runtime/mta_client_control_frame.py',
    'host/receive_directory_auth_clock_check.py', 'HOST_MTA_RECEIVE_DIRECTORY_AUTH_CLOCK_CHECK.cmd')
MARKER = (b'HOST_RECEIVE_DIRECTORY_AUTH_CLOCK new_methods=1 old_methods=0 cases=4 '
    b'filesystem_model=true binding_model=true device=false phone=false\n')


def main():
    if len(sys.argv) != 1:
        return 2
    if sys.version_info[:2] != (3, 12):
        raise ValueError('fixed_HOST_python312_required')
    originals = {name: (BASE / name).read_bytes() for name in SOURCES}
    for name, pin in ((TEST, TEST_PIN), (F, F_PIN)):
        if len(originals[name]) != pin[0] or hashlib.sha256(originals[name]).hexdigest() != pin[1]:
            raise ValueError('fixed_input_changed')
    # One changed F only; no old Storage/Transport/codec/Protocol AST replay.
    ast.parse(originals[F].decode('utf-8'), filename=F, feature_version=(3, 5))
    out = BASE / 'results' / ('receive-directory-auth-clock-host-' +
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
        child = subprocess.run([sys.executable, '-I', '-B', str(private / TEST), METHOD],
            cwd=private, capture_output=True, timeout=45)
        stdout, stderr, code = child.stdout, child.stderr, child.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code = error.stdout or b'', error.stderr or b'', None
        timed_out = True
    (out / 'stdout.raw').write_bytes(stdout)
    (out / 'stderr.raw').write_bytes(stderr)
    unchanged = all((BASE / name).read_bytes() == raw and (private / name).read_bytes() == raw
        for name, raw in originals.items())
    summary_ok = re.fullmatch(br'\.\n-+\nRan 1 test in [0-9]+\.[0-9]+s\n\nOK\n',
        stderr.replace(b'\r\n', b'\n')) is not None
    passed = code == 0 and not timed_out and unchanged and stdout in (MARKER, MARKER.replace(b'\n', b'\r\n')) and summary_ok
    report = dict(schema='receive-directory-auth-clock-host-v2', passed=passed,
        child_exit=code, timeout=timed_out, child_invocations=1, new_methods=1, old_methods=0,
        completed_domains=4 if passed else None, source_snapshots_equal=unchanged,
        target_python35_ast_sources=1, target_ast_path=F, snapshot_count=len(originals),
        actual_F_authentication_tested=passed, actual_control_codec_tested=passed,
        original_monotonic_clock=True, filesystem_model=True, binding_model=True, source_owner_model=True,
        directory_FD_tested=False, factory_published=False, loader_graph_loaded=False,
        parent_started=False, native_tested=False, device_accessed=False, rf_requested=False,
        receive_available=False, production_admission=False, restoration_verified=False, phone_tested=False,
        private_raw_included=False,
        inputs=[dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            for name, raw in originals.items()],
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest())
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'One new F authenticate method, four clock/cap/identity cases. Complete verified F and pure control '
        b'codec definitions; FS/Binding/source-owner ancestry are explicit models, with actual monotonic clock. '
        b'No old test, Factory publication, full Loader.load, Parent, physical directory FD, Native, RF, device, '
        b'phone, production admission or restoration. Only changed F Python 3.5 AST; raw/snapshots private.\n')
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
