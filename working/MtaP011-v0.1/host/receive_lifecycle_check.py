"""PC-only affected lifecycle methods, one new method and explicit HOST seams."""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
TEST = 'tests/test_client_receive_lifecycle_v1.py'
RUNTIME = 'candidate/client-receive-lifecycle-v1/runtime/'
SOURCES = (TEST, RUNTIME + 'mta_service.py', RUNTIME + 'mta_client_receive_boot.py',
    RUNTIME + 'mta_client_service_owner.py',
    'candidate/go-send-state-v78/runtime/mta_transfer_session.py',
    'host/receive_lifecycle_check.py', 'HOST_MTA_RECEIVE_LIFECYCLE_CHECK.cmd')
MARKER = (b'HOST_RECEIVE_LIFECYCLE new_methods=1 old_methods=0 cases=6 '
    b'functions_only=true session78_actual=true full_graph=false '
    b'fs_fixture=true http_actor_fixture=true native_restore_fixture=true '
    b'receive_admission=false device=false phone=false\n')


def main():
    if len(sys.argv) != 1:
        return 2
    out = BASE / 'results' / ('receive-lifecycle-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    private = out / 'private-inputs'
    private.mkdir(parents=True)
    originals = {path: (BASE / path).read_bytes() for path in SOURCES}
    for path, raw in originals.items():
        dest = private / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        if dest.read_bytes() != raw:
            raise ValueError('source_snapshot_changed')
    # Only these three changed target sources, not old unchanged graph suites.
    for path in SOURCES[1:4]:
        ast.parse(originals[path].decode('utf-8'), feature_version=(3, 5))
    timed_out = False
    try:
        child = subprocess.run([sys.executable, '-I', '-B', str(private / TEST)],
            cwd=private, capture_output=True, timeout=30)
        stdout, stderr, code = child.stdout, child.stderr, child.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code = error.stdout or b'', error.stderr or b'', None
        timed_out = True
    (out / 'stdout.raw').write_bytes(stdout)
    (out / 'stderr.raw').write_bytes(stderr)
    unchanged = all((BASE / path).read_bytes() == raw and (private / path).read_bytes() == raw
                    for path, raw in originals.items())
    passed = (code == 0 and not timed_out and unchanged and
        stdout in (MARKER, MARKER.replace(b'\n', b'\r\n')) and
        b'Ran 1 test' in stderr and stderr.rstrip().endswith(b'OK'))
    report = dict(passed=passed, child_exit=code, timeout=timed_out, child_invocations=1,
        new_methods=1, new_domains=6 if passed else None, old_methods=0,
        affected_python35_ast_sources=3, sources_preserved=unchanged,
        inputs=[dict(path=path, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                for path, raw in originals.items()],
        actual_affected_function_bodies=passed, actual_session78=passed,
        fs_fixture=True, http_actor_fixture=True, native_restore_fixture=True,
        full_boot_loaded=False, state_constructor_tested=False, native_restoration_verified=False,
        device=False, phone=False, rf=False, production_admission=False,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest())
    result = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'New HOST-only receive lifecycle affected-function test, one method and six domains. '
        b'Actual original Operation and selected State/Owner method bodies plus actual Session78. '
        b'Constructors, filesystem authority, HTTP actors and native restore are explicit fixtures. '
        b'No full Boot/F graph, P011, phone, RF, physical restore or production admission. '
        b'Only three changed runtime syntax checks. Original raw and input snapshots remain private.\n')
    (out / 'result.json').write_bytes(result)
    (out / 'README.txt').write_bytes(readme)
    members = {'result.json': result, 'README.txt': readme}
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in members.items():
            bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != list(members) or bundle.testzip() is not None or any(bundle.read(k) != v for k, v in members.items()):
            raise ValueError('zip_readback_failed')
    print(json.dumps(dict(passed=passed, child_exit=code, timeout=timed_out,
        result_dir=str(out), result_zip=str(archive), zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
