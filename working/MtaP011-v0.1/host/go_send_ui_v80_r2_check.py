"""One fixed Windows HOST Qt UI80-R2 child, six remaining inert-HTTP fixtures.

R1 wholeFAIL remains immutable; fixtures1-2 are not replayed or combined into
an eight-fixture PASS. The new remaining-six test SOURCE is fixed below.

The author only writes/reads/hashes SOURCE. ROOT owns the first execution.
Six private source copies, fixed Python 3.12 -I -B, 30 seconds, no retry.
No old test, Qt5.10 target, service, RF, phone or transfer is invoked. Public
raw and the unedited HOST PNG require all strict success gates; failure raw
stay private. The fixed test overrides HTTP request(), not real XHR callbacks.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import time
import uuid
import zipfile
import zlib


BASE = Path(__file__).resolve().parents[1]
CHECKER = 'host/go_send_ui_v80_r2_check.py'
TEST = 'tests/test_go_send_ui_v80_r2.py'
TEST_BYTES = 23421
TEST_SHA256 = '1baf93614ec46977742e3ed17792d8dae74b5ff3d1aacfb2e8557cbb9ce28008'
METHOD = 'GoSendUi80R2Test.test_remaining_selection_busy_restore_and_epoch_gates'
FIXED = (
    ('candidate/go-send-ui-v80/device/MtaPage.qml', 25341,
     '2729358896390175557a2ec907286f8413fa600d0dee0397517ae4c9cd133c0a'),
    ('device/MtaButton.qml', 757,
     '5abb4dabbd735ef4a071e8e10a65cf5c946e505cceb2373a12fa5f54827d1339'),
    ('device/MtaLabel.qml', 351,
     'e6298ebb141e4eba23b7acd1dee6900c141d1065ed194be953d1b3daff77eaa3'),
    ('device/MtaTheme.js', 261,
     'b795cd24c1bae4c9423c6c9c3e45303b0494c267a897715c4f8eab14f8f12f2c'),
    (TEST, TEST_BYTES, TEST_SHA256),
)
ORIGINAL = ('device/MtaPage.qml', 22517,
            'be3d9bbdae4c0fc109ae984727b78b5a6d910be2bff7be6d6fa0086d3cdd64b0')
PYTHON = Path('C:/Users/P011_USER/AppData/Local/Programs/Python/Python312/python.exe')
PYTHON_PIN = (103192, '42ac541168e97dedb9aabd8be335539fc41c682e414b9e8d137b164fb68683b0')
MARKER = (b'HOST80R2_GO_SEND_UI new_methods=1 old_methods=0 cases=6 '
          b'qt_host=true http_model=true device=false phone=false\n')
SCREENSHOT = 'host-ui80.png'
CHILD_SECONDS = 30
PNG_LIMIT = 4 * 1024 * 1024
SUMMARY = rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n'
QT_SAFE_LINES = (
    b'This plugin does not support propagateSizeHints()',
    b'This plugin does not support raise()',
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def original_matches():
    path, size, digest = ORIGINAL
    raw = (BASE / path).read_bytes()
    return len(raw) == size and sha(raw) == digest


def verify():
    if (os.name != 'nt' or sys.version_info[:2] != (3, 12) or
            os.path.normcase(str(Path(sys.executable).resolve())) !=
            os.path.normcase(str(PYTHON.resolve()))):
        raise ValueError('fixed_windows_python_required')
    binary = PYTHON.read_bytes()
    if len(binary) != PYTHON_PIN[0] or sha(binary) != PYTHON_PIN[1]:
        raise ValueError('fixed_python_changed')
    inputs = {CHECKER: Path(__file__).read_bytes()}
    for path, size, digest in FIXED:
        raw = (BASE / path).read_bytes()
        if len(raw) != size or sha(raw) != digest:
            raise ValueError('fixed_source_changed')
        inputs[path] = raw
    if len(inputs) != 6 or not original_matches():
        raise ValueError('original_page_or_input_count_changed')
    # The full test SOURCE is pinned; its __main__ builds only METHOD's suite.
    # No old method inventory or test definitions are imported by the checker.
    return inputs


def review_stderr(raw):
    """Allow only bounded exact non-identifying Qt platform constants."""
    count = 0
    remaining = raw
    while count < 8:
        matched = False
        for line in QT_SAFE_LINES:
            for ending in (b'\r\n', b'\n'):
                prefix = line + ending
                if remaining.startswith(prefix):
                    remaining = remaining[len(prefix):]
                    count += 1
                    matched = True
                    break
            if matched:
                break
        if not matched:
            break
    return re.fullmatch(SUMMARY, remaining) is not None, count


def png_facts(raw):
    """Check the actual file without image editing or Qt import in parent."""
    if not 100 < len(raw) <= PNG_LIMIT or raw[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('host_png_invalid')
    offset, chunks, idat, width, height = 8, 0, 0, None, None
    ended = False
    while offset < len(raw):
        if ended or offset + 12 > len(raw):
            raise ValueError('host_png_chunks_invalid')
        length = struct.unpack('!I', raw[offset:offset + 4])[0]
        kind = raw[offset + 4:offset + 8]
        end = offset + 12 + length
        if length > PNG_LIMIT or end > len(raw):
            raise ValueError('host_png_chunk_size_invalid')
        data = raw[offset + 8:offset + 8 + length]
        crc = struct.unpack('!I', raw[offset + 8 + length:end])[0]
        if (zlib.crc32(kind + data) & 0xffffffff) != crc:
            raise ValueError('host_png_crc_invalid')
        if chunks == 0:
            if kind != b'IHDR' or length != 13:
                raise ValueError('host_png_header_invalid')
            width, height, depth, colour, compression, filtering, interlace = struct.unpack('!IIBBBBB', data)
            if ((width, height) != (800, 268) or depth != 8 or colour not in (2, 6) or
                    compression != 0 or filtering != 0 or interlace not in (0, 1)):
                raise ValueError('host_png_dimensions_or_format_invalid')
        elif kind == b'IHDR':
            raise ValueError('host_png_duplicate_header')
        if kind == b'IDAT':
            idat += 1
        if kind == b'IEND':
            if length != 0 or end != len(raw) or not idat:
                raise ValueError('host_png_end_invalid')
            ended = True
        chunks += 1
        if chunks > 4096:
            raise ValueError('host_png_chunk_count_invalid')
        offset = end
    if not ended:
        raise ValueError('host_png_incomplete')
    return dict(bytes=len(raw), sha256=sha(raw), width=width, height=height,
                chunk_count=chunks, chunk_crc_verified=True)


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY fixed HOST Qt UI check; no device/network/path arguments')
        return 2
    output = BASE / 'results' / ('go-send-ui-v80-r2-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    inputs, rows = {}, []
    private, verified, before, error = None, False, False, None
    try:
        inputs = verify()
        before = True
        private = output / 'private-inputs' / 'project' / 'working' / 'MtaP011-v0.1'
        for path, raw in sorted(inputs.items()):
            destination = private / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('xb') as handle:
                handle.write(raw)
            if destination.read_bytes() != raw:
                raise ValueError('private_copy_changed')
            rows.append(dict(path=path, bytes=len(raw), sha256=sha(raw)))
        verified = True
    except (OSError, ValueError, UnicodeError):
        error = 'source_or_snapshot_invalid'
    stdout, stderr, code, timeout, invoked = b'', b'', None, False, False
    started = time.monotonic()
    if verified:
        env = dict(os.environ)
        env.pop('PYTHONPATH', None)
        env.pop('PYTHONSTARTUP', None)
        try:
            invoked = True
            child = subprocess.run([str(PYTHON), '-I', '-B', str(private / TEST), '-q'],
                cwd=str(private), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=CHILD_SECONDS, check=False)
            stdout, stderr, code = child.stdout, child.stderr, child.returncode
        except subprocess.TimeoutExpired as failure:
            stdout, stderr, timeout = failure.stdout or b'', failure.stderr or b'', True
        except OSError:
            error = 'child_not_started'
    elapsed = time.monotonic() - started
    (output / 'stdout.raw').write_bytes(stdout)
    (output / 'stderr.raw').write_bytes(stderr)
    preserved, fixed_preserved = False, False
    try:
        preserved = original_matches()
        fixed_preserved = bool(inputs) and all((BASE / path).read_bytes() == raw for path, raw in inputs.items())
    except OSError:
        pass
    image, screenshot = None, None
    if invoked and private is not None:
        try:
            capture = private / SCREENSHOT
            metadata = capture.lstat()
            if not stat.S_ISREG(metadata.st_mode) or not 100 < metadata.st_size <= PNG_LIMIT:
                raise ValueError('host_capture_not_regular')
            image = capture.read_bytes()
            screenshot = png_facts(image)
            if len(image) != metadata.st_size:
                raise ValueError('host_capture_size_changed')
            with (output / SCREENSHOT).open('xb') as handle:
                handle.write(image)
            if (output / SCREENSHOT).read_bytes() != image or capture.read_bytes() != image:
                raise ValueError('host_capture_readback_changed')
        except (OSError, ValueError, struct.error):
            image, screenshot = None, None
            if error is None:
                error = 'host_capture_invalid_or_missing'
    stdout_ok = stdout in (MARKER, MARKER.replace(b'\n', b'\r\n'))
    stderr_ok, hints = review_stderr(stderr)
    passed = (verified and invoked and code == 0 and not timeout and stdout_ok and stderr_ok and
              before and preserved and fixed_preserved and screenshot is not None and error is None)
    value = dict(schema='go-send-ui-v80-r2-host', passed=passed,
        source_verified=verified, source_snapshot_count=len(rows), inputs=rows,
        new_methods=[METHOD], completed_fixtures=6 if passed else None,
        earlier_ui80_result='results/go-send-ui-v80-host-20261003-073255-c0e4b9d7',
        earlier_ui80_whole_passed=False, earlier_ui80_first_two_assertions_reached=True,
        earlier_ui80_first_two_replayed=False, combined_eight_fixture_passed=False,
        scope_only_remaining_fixtures_3_to_8=True,
        child_invocations=int(invoked), old_test_methods_invoked=0,
        python312_executable_verified=verified, child_isolated=True, child_bytecode_disabled=True,
        host_exit=code, timeout=timeout, host_elapsed_seconds=elapsed,
        child_timeout_seconds=CHILD_SECONDS, verification_error=error,
        qt_host=True, http_model=True, late_xhr=False, device=False, phone=False,
        send_available=False, restore=False, rf=False, production_admission=False,
        actual_qt_host_cases_tested=passed, actual_mousearea_handlers_tested=passed,
        actual_http_service_tested=False, actual_file_transfer_tested=False,
        p011_qt510_tested=False, physical_touch_tested=False, physical_display_tested=False,
        old_test_replayed=False, candidate_deployed=False, bundled_fonts_added=False,
        fixture_send_capability_is_model=True, progress_does_not_grant_completion=True,
        original_qml_pre_verified=before, original_qml_post_verified=preserved,
        original_qml_preserved=before and preserved, fixed_sources_preserved=fixed_preserved,
        stdout_fixed_marker_reviewed=stdout_ok, stderr_unittest_reviewed=stderr_ok,
        stderr_safe_qt_constant_count=hints, stdout_bytes=len(stdout), stderr_bytes=len(stderr),
        stdout_sha256=sha(stdout), stderr_sha256=sha(stderr),
        screenshot=screenshot, screenshot_actual_host=True if screenshot is not None else False,
        screenshot_edited=False, screenshot_fixture_labels_only=True,
        screenshot_public_included=passed, public_raw_included=passed,
        public_zip_member_count=5 if passed else 2)
    result = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (
        'PC-only HOST Qt UI80-R2: one new method, six remaining fresh fixtures3-8, one fixed '
        'Python3.12 -I -B child, 30 seconds, no retry and no old test replay. '
        'Six private source snapshots. Actual frozen QML and MouseArea handlers; '
        'request() is an inert in-memory HTTP fixture, not a server or real XHR. '
        'Late XHR callback guards are not tested. Actual unedited HOST capture '
        '800x268 shows fixed HOST labels, not a physical P011 display. '
        'HOST Qt5.15 is not P011 Qt5.10.1, touch, phone, GATT, RF, usable send, '
        'admission, peer completion or restoration. Original page pre/post pins '
        'and all six fixed source bytes must match. Success raw require exact '
        'marker, Ran1/OK, exit0, no timeout; only bounded fixed non-identifying '
        'Qt platform constants are allowed before the unittest summary. '
        'PNG dimensions, chunk CRC, SHA and saved byte readback are verified. '
        'Success ZIP contains result/README/raw/actual HOST PNG; failure ZIP '
        'contains only result and README. All failure raw stay private. '
        'R1 results/go-send-ui-v80-host-20261003-073255-c0e4b9d7 remains wholeFAIL; '
        'its first two fixture assertions were reached and are not replayed. '
        'R2 tests only the six remaining fixtures, never combines eight into PASS. '
        'Previous source and results are not replaced.\n').encode('ascii')
    (output / 'result.json').write_bytes(result)
    (output / 'README.txt').write_bytes(readme)
    members = {'result.json': result, 'README.txt': readme}
    if passed:
        members.update({'stdout.raw': stdout, 'stderr.raw': stderr, SCREENSHOT: image})
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
