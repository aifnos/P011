"""One new PC-only real component integration; immutable inputs and safe ZIP."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
TEST = 'tests/test_receive_filecenter_integration.py'
SOURCES = (TEST, 'host/receive_filecenter_integration_check.py',
    'tests/test_sender_pump.py', 'runtime/mta_sender_pump.py',
    'runtime/mta_send_preparation.py', 'runtime/mta_transport.py',
    'runtime/mta_protocol.py', 'runtime/p011_json.py',
    'candidate/file-utf8-v67/runtime/mta_files.py',
    'candidate/file-utf8-v67/runtime/mta_storage.py',
    'integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py')


def main():
    if len(sys.argv) != 1:
        return 2
    out = BASE / 'results' / ('receive-filecenter-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    private = out / 'private-inputs'
    private.mkdir(parents=True)
    sources = {path: (BASE / path).read_bytes() for path in SOURCES}
    for path, raw in sources.items():
        destination = private / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        if destination.read_bytes() != raw:
            raise ValueError('snapshot_changed')
    openssl = Path(r'C:\Program Files\Git\mingw64\bin\openssl.exe')
    openssl_raw = openssl.read_bytes()
    openssl_pin = (len(openssl_raw), hashlib.sha256(openssl_raw).hexdigest())
    env = dict(os.environ)
    env.pop('PYTHONPATH', None)
    env.pop('PYTHONSTARTUP', None)
    started = time.monotonic()
    timed_out = False
    try:
        child = subprocess.run([sys.executable, '-I', '-B', str(private / TEST), '-q'],
            cwd=private, env=env, capture_output=True, timeout=45)
        stdout, stderr, child_exit = child.stdout, child.stderr, child.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, child_exit = error.stdout or b'', error.stderr or b'', None
        timed_out = True
    elapsed = time.monotonic() - started
    (out / 'stdout.raw').write_bytes(stdout)
    (out / 'stderr.raw').write_bytes(stderr)
    result = None
    try:
        lines = stdout.decode('ascii').splitlines()
        if len(lines) == 1 and lines[0].startswith('RESULT='):
            result = json.loads(lines[0][7:])
    except (UnicodeError, ValueError):
        pass
    unchanged = all((BASE / path).read_bytes() == raw for path, raw in sources.items())
    openssl_after = openssl.read_bytes()
    openssl_unchanged = (len(openssl_after), hashlib.sha256(openssl_after).hexdigest()) == openssl_pin
    passed = (child_exit == 0 and not timed_out and unchanged and openssl_unchanged and
        result is not None and result.get('passed') is True and result.get('new_methods') == 1 and
        result.get('old_methods') == 0 and b'Ran 1 test' in stderr and stderr.rstrip().endswith(b'OK'))
    report = dict(schema='receive-filecenter-host-integration', passed=passed,
        child_exit=child_exit, timeout=timed_out, child_invocations=1, elapsed_seconds=elapsed,
        sources_preserved=unchanged, openssl_preserved=openssl_unchanged,
        inputs=[dict(path=path, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) for path, raw in sources.items()],
        openssl=dict(bytes=openssl_pin[0], sha256=openssl_pin[1]),
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        integration=result, device_tested=False, phone_tested=False, production_receive_available=False)
    raw_result = (json.dumps(report, indent=2, ensure_ascii=True) + '\n').encode('ascii')
    (out / 'result.json').write_bytes(raw_result)
    readme = (b'New HOST-only real PreparedSend -> SenderPump -> ReceiverTransport -> SafeZipReceiver -> '
        b'FileRegistry -> FileStore integration. One new method, no old methods run. '
        b'Actual two TCP/TLS connections, consent blocks download, Chinese file bytes/commit/ACK and cleanup. '
        b'Loopback constructor admission and existing HOST socket owner are explicit fixtures. '
        b'Not State/F admission, P011, phone, RF or physical network restoration. '
        b'Private input snapshots, failure raw and keys are excluded from this ZIP.\n')
    (out / 'README.txt').write_bytes(readme)
    archive = out / 'public-result.zip'
    members = {'result.json': raw_result, 'README.txt': readme}
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, data in members.items():
            bundle.writestr(name, data)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None or bundle.namelist() != list(members) or any(bundle.read(k) != v for k, v in members.items()):
            raise ValueError('zip_readback_failed')
    print(json.dumps(dict(passed=passed, child_exit=child_exit, timeout=timed_out,
        elapsed_seconds=elapsed, result_dir=str(out), result_zip=str(archive),
        zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
