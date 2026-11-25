"""One new affected clock/binding constructor method; HOST WSL, no network."""
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
TEST = 'tests/test_receive_directory_clock.py'
RUNTIME = 'candidate/receive-directory-clock-v2/runtime/mta_transport.py'
SOURCES = (TEST, RUNTIME, 'candidate/receive-directory-fd-v1/runtime/mta_storage.py', 'runtime/mta_protocol.py', 'runtime/p011_json.py',
    'host/receive_directory_clock_check.py', 'HOST_MTA_RECEIVE_DIRECTORY_CLOCK_CHECK.cmd')
MARKER = (b'HOST_RECEIVE_DIRECTORY_CLOCK new_methods=1 old_methods=0 cases=4 '
    b'linux_kernel=true device=false phone=false\n')


def _wsl_path(path):
    text = str(path)
    if len(text) < 3 or text[1:3] != ':\\' or text[0].lower() != 'd':
        raise ValueError('fixed_workspace_required')
    return '/mnt/d/' + text[3:].replace('\\', '/')


def main():
    if len(sys.argv) != 1:
        return 2
    originals = {name: (BASE / name).read_bytes() for name in SOURCES}
    ast.parse(originals[RUNTIME].decode('utf-8'), feature_version=(3, 5))
    out = BASE / 'results' / ('receive-directory-clock-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    private = out / 'private-inputs'
    for name, raw in originals.items():
        target = private / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        if target.read_bytes() != raw:
            raise ValueError('snapshot_changed')
    argv = ['wsl.exe', '-d', 'kali-linux', '--exec', '/usr/bin/python3',
        '-I', '-B', _wsl_path(private / TEST)]
    timed_out = False
    try:
        child = subprocess.run(argv, cwd=private, capture_output=True, timeout=45)
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
    if startup_warning:derived = derived[len(warning):]
    summary_ok = re.fullmatch(br'\.\n-+\nRan 1 test in [0-9]+\.[0-9]+s\n\nOK\n', derived) is not None
    passed = code == 0 and not timed_out and unchanged and stdout == MARKER and summary_ok
    report = dict(passed=passed, child_exit=code, timeout=timed_out,
        child_invocations=1, new_methods=1, old_methods=0, new_domains=4 if passed else None,
        wsl_user_session_warning=startup_warning,
        host_linux_kernel_tested=passed, actual_p011=False, phone=False,
        production_receive_admission=False, network_or_rf=False,
        source_snapshots_equal=unchanged, target_python35_ast_sources=1,
        inputs=[dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            for name, raw in originals.items()],
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        private_raw_included=False)
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'One new affected ReceiverTransport constructor/check method, four domains on HOST Linux. '
        b'Actual private filesystem/binding; HOST wrapper clock calls original time.monotonic. '
        b'No socket connect, old test method, P011, native lease identity, RF, phone or production admission. '
        b'Only changed Transport Python 3.5 syntax is checked. Raw and input snapshots remain private.\n')
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
