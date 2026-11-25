"""One fixed HOST Qt check of new open-file navigation; no device or media IO.

Private copies only, one bounded child, no retry. Success raw are limited to a
fixed marker and unittest summary. The inert app/media fixtures are explicit;
HOST Qt is not P011 Qt 5.10, physical playback, touch or MTA interoperability.
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
CHECKER = 'host/file_navigation_v68_r2_check.py'
TEST = 'tests/test_file_navigation_v68_r2.py'
FIXED = (
    ('candidate/file-navigation-v68/device/FilesPage.qml', 12524, '34ecbd37bb0eabe36bf4f6d0a64086f29fe28340df54dbb97c066387e48ec523'),
    ('integration/ToolboxMta-v0.1/device/Theme.js', 244, '308cc441d29a5d39e61e0418ad0b4dfbb3efa2be6ce0bf6e80577c73479d2edb'),
    ('integration/ToolboxMta-v0.1/device/Button.qml', 665, 'ef4f1f83c198ae40e56982eec7d1ee87d36185fae9bbf1b15ea8853b64dcb015'),
    ('integration/ToolboxMta-v0.1/device/Label.qml', 269, '4f109dd7591c7363dc95883ca2c13cf43c3b9c9f461d72238d1567a52bd949fc'),
    (TEST, 15496, 'bdd51ef0f99e22f5f219e12c0efb90b0a2b5816d3977d6e1d3ee3b0a9d43f9da'),
)
ORIGINAL = ('integration/ToolboxMta-v0.1/device/FilesPage.qml', 11950,
            '0ddd55b774e2ce9986f681886da2e69763e539d905de5dfb467e553a5ad32832')
MARKER = b'HOST68_FILE_NAV new_methods=1 cases=8 old_methods=0 qt_host=true device=false physical_playback=false\n'
CHILD_SECONDS = 60


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def original_matches():
    path, size, digest = ORIGINAL
    raw = (BASE / path).read_bytes()
    return len(raw) == size and sha(raw) == digest


def verify():
    inputs = {CHECKER: Path(__file__).read_bytes()}
    for path, size, digest in FIXED:
        raw = (BASE / path).read_bytes()
        if len(raw) != size or sha(raw) != digest:
            raise ValueError('fixed_source_changed')
        inputs[path] = raw
    if not original_matches():
        raise ValueError('original_page_changed')
    parsed = ast.parse(inputs[TEST].decode('utf-8'))
    methods = [node.name + '.' + child.name for node in parsed.body
        if isinstance(node, ast.ClassDef) for child in node.body
        if isinstance(child, ast.FunctionDef) and child.name.startswith('test_')]
    if methods != ['FileNavigationV68Tests.test_only_new_open_epoch_path_navigation_and_loading_ownership'] or len(inputs) != 6:
        raise ValueError('new_method_inventory_changed')
    return inputs, methods


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY fixed Qt navigation check; no device/network/path arguments')
        return 2
    output = BASE / 'results' / ('file-navigation-v68-r2-host-' +
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
    preserved = False
    try:
        preserved = original_matches()
    except OSError:
        pass
    stdout_ok = stdout in (MARKER, MARKER.replace(b'\n', b'\r\n'))
    stderr_ok = re.fullmatch(rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n', stderr) is not None
    passed = verified and invoked and code == 0 and not timeout and stdout_ok and stderr_ok and preserved
    value = dict(schema='file-navigation-v68-r2-host', passed=passed,
        source_verified=verified, source_snapshot_count=len(rows), inputs=rows,
        new_methods=methods, completed_cases=8 if passed else None,
        child_invocations=int(invoked), old_test_methods_invoked=0,
        host_exit=code, timeout=timeout, host_elapsed_seconds=elapsed,
        child_timeout_seconds=CHILD_SECONDS, verification_error=error,
        actual_candidate_qml_navigation_tested=passed,
        app_requests_are_in_memory_fixtures=True,
        audio_dispatch_is_derived_inert_fixture=True, video_pane_is_inert_fixture=True,
        original_audio_response_lifecycle_tested=False,
        p011_qt510_ui_tested=False, touch_tested=False, physical_playback_tested=False,
        p011_tested=False, phone_tested=False, device_accessed=False, rf_requested=False,
        network_service_started=False, receive_admission_enabled=False,
        p011_send_receive_available=False, actual_network_restore_verified=False,
        original_qml_preserved=preserved, original_qml_modified=False if preserved else None,
        candidate_not_deployed=True, original_v68_test_executed=False,
        stdout_fixed_marker_reviewed=stdout_ok, stderr_unittest_reviewed=stderr_ok,
        stdout_bytes=len(stdout), stderr_bytes=len(stderr),
        stdout_sha256=sha(stdout), stderr_sha256=sha(stderr),
        public_raw_included=passed, public_zip_member_count=4 if passed else 2)
    result = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (
        'PC-only HOST Qt: one new method, eight fresh page cases, one -I -B child, '
        '60 second limit, no retry and no old test replay. Six private source inputs. '
        'Actual candidate open callbacks and navigation; app requests are in-memory. '
        'Derived audio method and inert VideoPane only record dispatch, not playback. '
        'Independent original audio response lifecycle remains untested. '
        'HOST Qt is not P011 Qt 5.10, touch, phone, RF, service admission or recovery. '
        'Original page is preserved; candidate not deployed. Original v68 fixture '
        'had a SOURCE-only counter assertion defect and was never executed. '
        'Public raw require strict marker, Ran1/OK, exit0, no timeout and original hash. '
        'Failure raw stay private; previous results are not replaced.\n').encode('ascii')
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
