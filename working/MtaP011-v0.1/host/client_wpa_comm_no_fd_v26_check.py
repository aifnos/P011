"""One fixed new HOST source-policy model method; no AST or device access.

The old test file is used for pure fixture definitions only. No old TestCase
or test method is selected. Canonical fixture transitives are explicitly pinned
and snapshotted; only the new WPA source runs in a private definition module.
"""
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
TEST = 'tests/test_client_wpa_comm_no_fd_v26.py'
CHECKER = 'host/client_wpa_comm_no_fd_v26_check.py'
CMD = 'HOST_MTA_WPA_COMM_NO_FD_V26_CHECK.cmd'
PINS = (
    ('candidate/client-wpa-proc-vanish-v26/runtime/mta_client_wpa_status.py', 44902,
     'b1d9ce5ed37c7249952804f3bb2979fbb15492a57ac1514396bfa5d0e0103128'),
    (TEST, 15526, 'a4732769a73141d757f5197c93b4081300ecbb57bf65475f1696d27ab9e6db8b'),
    ('tests/test_client_wpa_status.py', 29939,
     'fd5db1a405c2a74e16cb1d0394dcb943a1f1bec29ed25b7931fc32a315cdd872'),
    ('runtime/mta_client_wpa_status.py', 39045,
     '4f0fa75132c8c81427f1d593fdc415b01657b061cd9d1dbcbcde789b52daf742'),
    ('runtime/mta_client_baseline.py', 29121,
     'ce8fe17b60964cf9b421296eef033d1dde19f8a4118de12d7f3922133ee13f08'),
    ('runtime/mta_client_proc.py', 25511,
     '2f0ef52379be897d47b5cb311ef90f24b5c8a2c283e72780f139a8dd77626591'),
    ('runtime/mta_p2p_client_init.py', 60748,
     'ec2d927c50bf2946614990bdd9fe1d69ce5538047573d9a4d885a3914b0f85f1'),
    ('runtime/mta_p2p_client_ctrl.py', 18712,
     '793b784f1b39eca18001aa65a1f0d6cdbd6de466dc58b3cf2ada167f71d902b5'),
    ('runtime/mta_ip.py', 22049,
     '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('runtime/mta_client_caps_transport.py', 19614,
     'df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420'),
    ('runtime/mta_client_caps.py', 11821,
     'c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c'),
)
MARKER = (b'HOST_WPA_COMM_NO_FD_V26 new_methods=1 domains=18 old_methods=0 '
          b'os_fixture_model=true arm_read_flags=true device=false rf=false '
          b'receive=false restoration=false\n')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_fixed(path, size, sha):
    if (type(path) is not str or path.startswith('/') or ':' in path or '\\' in path or
            any(part in ('', '.', '..') for part in path.split('/')) or
            type(size) is not int or size < 1 or type(sha) is not str or
            re.fullmatch('[0-9a-f]{64}', sha) is None):
        raise ValueError('fixed_input_shape')
    raw = (BASE / path).read_bytes()
    if (len(raw), digest(raw)) != (size, sha):
        raise ValueError('fixed_input_changed')
    return raw


def write_new(path, raw):
    with path.open('xb') as handle:
        handle.write(raw)
    if path.read_bytes() != raw:
        raise ValueError('file_readback')


def main():
    if len(sys.argv) != 1 or sys.version_info[:2] != (3, 12):
        raise ValueError('fixed_HOST_python312_no_arguments_required')
    out = BASE / 'results' / ('wpa-comm-no-fd-v26-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    snapshot = out / 'private-inputs'
    private = out / 'private-raw'
    private.mkdir(exist_ok=False)
    originals, error_kind = {}, None
    stdout = stderr = b''
    code, timed_out, invoked = None, False, False
    fixed_loaded = snapshot_written = False
    try:
        for path, size, sha in PINS:
            if path in originals:
                raise ValueError('duplicate_fixed_input')
            originals[path] = read_fixed(path, size, sha)
        # Self and CMD use actual read/hash rather than recursive self-pins.
        for path in (CHECKER, CMD):
            originals[path] = (BASE / path).read_bytes()
        if len(originals) != 13:
            raise ValueError('fixed_input_count')
        fixed_loaded = True
        for path, raw in originals.items():
            target = snapshot / path
            target.parent.mkdir(parents=True, exist_ok=True)
            write_new(target, raw)
        snapshot_written = True
        invoked = True
        try:
            child = subprocess.run([sys.executable, '-I', '-B', str(snapshot / TEST)],
                cwd=snapshot, capture_output=True, timeout=45)
            stdout, stderr, code = child.stdout, child.stderr, child.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr, code, timed_out = error.stdout or b'', error.stderr or b'', None, True
    except Exception as error:
        error_kind = type(error).__name__
    finally:
        # Never normalize or overwrite originals. Timeout is not exit/closure.
        write_new(private / 'child-stdout.raw', stdout)
        write_new(private / 'child-stderr.raw', stderr)
        write_new(private / 'child-exit', ((str(code) if type(code) is int else
            'TIMEOUT' if timed_out else 'NOT_COMPLETED') + '\n').encode('ascii'))
    unchanged = False
    try:
        unchanged = fixed_loaded and snapshot_written and len(originals) == 13 and all(
            (BASE / path).read_bytes() == raw and (snapshot / path).read_bytes() == raw
            for path, raw in originals.items())
    except OSError:
        unchanged = False
    derived_out = stdout.replace(b'\r\r\n', b'\n').replace(b'\r\n', b'\n')
    derived_err = stderr.replace(b'\r\r\n', b'\n').replace(b'\r\n', b'\n')
    marker_ok = derived_out == MARKER
    summary_ok = re.fullmatch(br'-+\nRan 1 test in [0-9]+\.[0-9]+s\n\nOK\n', derived_err) is not None
    passed = (error_kind is None and invoked and not timed_out and code == 0 and
              unchanged and marker_ok and summary_ok and len(stderr) > 0)
    report = dict(schema='wpa-comm-no-fd-v26-host-model', passed=passed,
        host_error=error_kind, child_invoked=invoked, child_exit=code, timeout=timed_out,
        child_timeout_seconds=45, original_stdout_bytes=len(stdout), original_stdout_sha256=digest(stdout),
        original_stderr_bytes=len(stderr), original_stderr_sha256=digest(stderr),
        marker_exact=marker_ok, one_new_method_summary=summary_ok,
        new_methods=1, old_methods=0, domains_completed=18 if passed else None,
        source_snapshots_equal=unchanged, snapshot_count=len(originals), fixed_input_count=13,
        no_python35_ast_replayed=True, actual_wpa_source_over_HOST_model=passed,
        os_fixture_model=True, arm_flags_model=True,
        device_accessed=False, actual_ARM_proc_read=False, actual_WPA_STATUS=False,
        hardware_FD_close_tested=False, RF_requested=False, phone_tested=False,
        old_pending_modified=False, receive_admission=False, restoration_verified=False,
        inputs=[dict(path=path, bytes=len(raw), sha256=digest(raw)) for path, raw in originals.items()],
        private_raw_included=False)
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'One new HOST method, eighteen narrow source-policy model domains. '
        b'The concrete fixed v26 WPA LinuxStatusSource read_source/authenticate_source run over explicit '
        b'HOST FakeIO/FakeProc assumptions in the original fixture core/proc/baseline realm. '
        b'ENOENT/ESRCH original known-unopened comm tickets remain unattempted; CloseProof covers '
        b'only real HOST-model returned FDs. Returned-FD errors, ineligible errno, mutated/duplicate/foreign '
        b'original receipts and missing required actors must refuse. ARM open flags are fixture assertions, '
        b'not platform verification. Historical definitions/fixtures are imported only; no old test runs. '
        b'Only one isolated -I -B child is invoked, with a 45-second timeout and preserved separate raw '
        b'stdout/stderr/exit. No AST replay, actual device/proc/WPA STATUS/hardware FD closure, RF, phone, '
        b'pending modification, receive admission or restoration proof. Fixed snapshots/raw remain '
        b'local/private; the public ZIP contains only this result and README.\n')
    members = {'result.json': public, 'README.txt': note}
    for path, raw in members.items():
        write_new(out / path, raw)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for path, raw in members.items():
            bundle.writestr(path, raw)
    with zipfile.ZipFile(archive) as bundle:
        if (bundle.namelist() != list(members) or bundle.testzip() is not None or
                any(bundle.read(path) != raw for path, raw in members.items())):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=passed, result_dir=str(out), result_zip=str(archive),
        zip_sha256=digest(archive.read_bytes())), sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
