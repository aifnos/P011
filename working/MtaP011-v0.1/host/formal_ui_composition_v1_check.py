"""Fixed PC-only formal-UI composition check; ROOT owns first execution.

One new Qt method, four new composition domains, one Python3.12 -I -B child
and a 30-second limit; no retry or old test invocation. Six frozen QML, four
existing wrapper parts, the test and provenance are literal-pinned. The checker
is externally frozen by ROOT and captured before/after; CMD is separately
literal-pinned. Fourteen private source copies must survive byte-for-byte.
Two actual unedited labelled HOST PNGs require 800x268 and valid chunk CRC.
Only success raw that matches exact marker/Ran1/OK constants can be public.
Failure raw/captures remain private. HTTP actions are in-memory fixtures;
there is no service, State, device, RF, phone or production admission.
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
CHECKER = 'host/formal_ui_composition_v1_check.py'
TEST = 'tests/test_formal_ui_composition_v1.py'
METHOD = 'FormalUiCompositionV1Tests.test_fixed_host_go_and_receive_composition'
FIXED = (
    ("candidate/formal-ui-v1/device/MtaTheme.js", 261,
     "b795cd24c1bae4c9423c6c9c3e45303b0494c267a897715c4f8eab14f8f12f2c"),
    ("candidate/formal-ui-v1/device/MtaPage.qml", 26088,
     "2e63016d806f890703c5d361b35cc80d2e092e55a2714088f27dcb948ef5c44e"),
    ("candidate/formal-ui-v1/device/MtaLabel.qml", 351,
     "e6298ebb141e4eba23b7acd1dee6900c141d1065ed194be953d1b3daff77eaa3"),
    ("candidate/formal-ui-v1/device/MtaKeyboard.qml", 5344,
     "3241344572163deff5bc195cfb06dc5647f76861c03736f99a331d5bb53ef661"),
    ("candidate/formal-ui-v1/device/MtaHost.qml", 6205,
     "371f705136fb1e03aec7d283120f6915b798edd4b96cdec670f29c971d508380"),
    ("candidate/formal-ui-v1/device/MtaButton.qml", 757,
     "5abb4dabbd735ef4a071e8e10a65cf5c946e505cceb2373a12fa5f54827d1339"),
    ("integration/ToolboxMta-v0.1/device/MtaEmbedded.qml", 6183,
     "4a86f69039054af1b0493338249310e5da4e6d49bf696c0b861fb45359d641ea"),
    ("integration/ToolboxMta-v0.1/device/Button.qml", 665,
     "ef4f1f83c198ae40e56982eec7d1ee87d36185fae9bbf1b15ea8853b64dcb015"),
    ("integration/ToolboxMta-v0.1/device/Label.qml", 269,
     "4f109dd7591c7363dc95883ca2c13cf43c3b9c9f461d72238d1567a52bd949fc"),
    ("integration/ToolboxMta-v0.1/device/Theme.js", 244,
     "308cc441d29a5d39e61e0418ad0b4dfbb3efa2be6ce0bf6e80577c73479d2edb"),
    ("tests/test_formal_ui_composition_v1.py", 19205,
     "141b27536daadcd31bd350802a1325184698b818974df98bb9da1bf353a00b33"),
    ("candidate/formal-ui-v1/SOURCE_PROVENANCE.json", 4059,
     "98cae1849a315e4536b8452aaad6230481988d3fbb27ebac305d273294bbd15a"),
)
COMMAND = ('HOST_MTA_FORMAL_UI_COMPOSITION_V1_CHECK.cmd', 751,
           '43c09b6c5b73fcd41e65fb0994557e9c13987356b55d323a8d49b09fe8513724')
PYTHON = Path('C:/Users/P011_USER/AppData/Local/Programs/Python/Python312/python.exe')
PYTHON_PIN = (103192, '42ac541168e97dedb9aabd8be335539fc41c682e414b9e8d137b164fb68683b0')
MARKER = (b'HOST_FORMAL_UI_COMPOSITION_V1 new_methods=1 old_methods=0 cases=4 '
          b'qt_host=true http_model=true service=false device=false phone=false\n')
CAPTURES = ('host-formal-ui-receive.png', 'host-formal-ui-go-wait.png')
CHILD_SECONDS = 30
PNG_LIMIT = 4 * 1024 * 1024
SUMMARY = rb'-{70}\r?\nRan 1 test in [0-9]+\.[0-9]+s\r?\n\r?\nOK\r?\n'
QT_SAFE_LINES = (
    b'This plugin does not support propagateSizeHints()',
    b'This plugin does not support raise()',
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_regular(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('source_not_regular')
    raw = path.read_bytes()
    after = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if (len(raw) != before.st_size or
            any(getattr(before, key) != getattr(after, key) for key in fields)):
        raise ValueError('readback_changed')
    return raw


def verify():
    if (os.name != 'nt' or sys.version_info[:2] != (3, 12) or
            os.path.normcase(str(Path(sys.executable).resolve())) !=
            os.path.normcase(str(PYTHON.resolve()))):
        raise ValueError('fixed_windows_python_required')
    binary = read_regular(PYTHON)
    if len(binary) != PYTHON_PIN[0] or sha(binary) != PYTHON_PIN[1]:
        raise ValueError('fixed_python_changed')
    inputs = {CHECKER: read_regular(BASE / CHECKER)}
    for path, size, digest in FIXED:
        raw = read_regular(BASE / path)
        if len(raw) != size or sha(raw) != digest:
            raise ValueError('fixed_source_changed')
        inputs[path] = raw
    path, size, digest = COMMAND
    command = read_regular(BASE / path)
    if len(inputs) != 13 or len(command) != size or sha(command) != digest:
        raise ValueError('input_count_or_command_changed')
    return inputs, command


def review_stderr(raw):
    """Only bounded exact non-identifying Qt constants before Ran1/OK."""
    count, remaining = 0, raw
    while count < 8:
        found = False
        for line in QT_SAFE_LINES:
            for ending in (b'\r\n', b'\n'):
                prefix = line + ending
                if remaining.startswith(prefix):
                    remaining = remaining[len(prefix):]
                    count += 1
                    found = True
                    break
            if found:
                break
        if not found:
            break
    return re.fullmatch(SUMMARY, remaining) is not None, count


def png_facts(raw):
    """Inspect actual PNG bytes without Qt import or image modification."""
    if not 100 < len(raw) <= PNG_LIMIT or raw[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('host_png_invalid')
    offset, chunks, idat, width, height, ended = 8, 0, 0, None, None, False
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


def save_new(path, raw):
    with path.open('xb') as handle:
        handle.write(raw)
    if read_regular(path) != raw:
        raise ValueError('saved_readback_changed')


def main():
    if len(sys.argv) != 1:
        print('PC_ONLY fixed HOST Qt check; no device/network/path arguments')
        return 2
    output = BASE / 'results' / ('formal-ui-composition-v1-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    inputs, rows, command, command_row = {}, [], None, None
    private, capture_dir, verified, error = None, None, False, None
    try:
        inputs, command = verify()
        private = output / 'private-inputs' / 'project' / 'working' / 'MtaP011-v0.1'
        for path, raw in sorted(inputs.items()):
            destination = private / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            save_new(destination, raw)
            rows.append(dict(path=path, bytes=len(raw), sha256=sha(raw)))
        save_new(private / COMMAND[0], command)
        command_row = dict(path=COMMAND[0], bytes=len(command), sha256=sha(command))
        capture_dir = output / 'private-captures'
        capture_dir.mkdir()
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
            child = subprocess.run([str(PYTHON), '-I', '-B', str(private / TEST),
                '--capture-directory', str(capture_dir)], cwd=str(private), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=CHILD_SECONDS, check=False)
            stdout, stderr, code = child.stdout, child.stderr, child.returncode
        except subprocess.TimeoutExpired as failure:
            stdout, stderr, timeout = failure.stdout or b'', failure.stderr or b'', True
        except OSError:
            error = 'child_not_started'
    elapsed = time.monotonic() - started
    save_new(output / 'stdout.raw', stdout)
    save_new(output / 'stderr.raw', stderr)
    sources_preserved, command_preserved, snapshots_preserved = False, False, False
    try:
        sources_preserved = bool(inputs) and all(read_regular(BASE / path) == raw
                                                for path, raw in inputs.items())
        command_preserved = command is not None and read_regular(BASE / COMMAND[0]) == command
        snapshots_preserved = (private is not None and bool(inputs) and
            all(read_regular(private / path) == raw for path, raw in inputs.items()) and
            command is not None and read_regular(private / COMMAND[0]) == command)
    except (OSError, ValueError):
        pass
    images, screenshots = {}, {}
    if invoked and capture_dir is not None:
        try:
            if {path.name for path in capture_dir.iterdir()} != set(CAPTURES):
                raise ValueError('host_capture_inventory_invalid')
            for name in CAPTURES:
                raw = read_regular(capture_dir / name)
                facts = png_facts(raw)
                if read_regular(capture_dir / name) != raw:
                    raise ValueError('host_capture_readback_changed')
                images[name], screenshots[name] = raw, facts
        except (OSError, ValueError, struct.error):
            images, screenshots = {}, {}
            if error is None:
                error = 'host_capture_invalid_or_missing'
    stdout_ok = stdout in (MARKER, MARKER.replace(b'\n', b'\r\n'))
    stderr_ok, hints = review_stderr(stderr)
    passed = (verified and invoked and code == 0 and not timeout and stdout_ok and stderr_ok and
              sources_preserved and command_preserved and snapshots_preserved and
              set(screenshots) == set(CAPTURES) and error is None)
    if passed:
        for name in CAPTURES:
            save_new(output / name, images[name])
    value = dict(schema='formal-ui-composition-v1-host', passed=passed,
        source_verified=verified, source_snapshot_count=len(rows), inputs=rows,
        command_snapshot=command_row, private_snapshot_count=len(rows) + int(command_row is not None),
        new_methods=[METHOD], completed_fixtures=4 if passed else None,
        child_invocations=int(invoked), old_test_methods_invoked=0, retry=False,
        python312_executable_verified=verified, python_executable_sha256=PYTHON_PIN[1],
        child_isolated=True, child_bytecode_disabled=True, child_exit=code,
        timeout=timeout, elapsed_seconds=elapsed, child_timeout_seconds=CHILD_SECONDS,
        verification_error=error, qt_host=True, status_model=True, http_model=True,
        service=False, fixed_wrapper_host_loaded=passed, go_receive_composition_tested=passed,
        late_xhr=False, network=False, device=False, phone=False, rf=False,
        qt_platform='windows', qt_software_backend=True, brief_host_window=True,
        receive_available=False, send_available=False, restore=False, production_admission=False,
        actual_qt_host_cases_tested=passed, state_constructed=False, transport_executed=False,
        archive_download_executed=False, crc_or_commit_verified=False, peer_ack_verified=False,
        p011_qt510_tested=False, physical_touch_tested=False, physical_display_tested=False,
        old_test_replayed=False, candidate_deployed=False, bundled_fonts_added=False,
        archive_total_invented=False, progress_does_not_grant_completion=True,
        root_qml_pre_verified=verified, root_qml_post_verified=sources_preserved,
        fixed_sources_preserved=sources_preserved, command_preserved=command_preserved,
        private_snapshot_bytes_preserved=snapshots_preserved,
        stdout_fixed_marker_reviewed=stdout_ok, stderr_unittest_reviewed=stderr_ok,
        stderr_safe_qt_constant_count=hints, stdout_bytes=len(stdout), stderr_bytes=len(stderr),
        stdout_sha256=sha(stdout), stderr_sha256=sha(stderr), screenshots=screenshots,
        screenshot_actual_host=len(screenshots) == 2, screenshot_edited=False,
        screenshot_fixture_labels_only=True, screenshot_public_included=passed,
        public_raw_included=passed, public_zip_member_count=6 if passed else 2,
        zip_verification_required=True)
    result = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = "PC-only formal UI composition: one new method, four new composition domains, one fixed Python3.12 -I -B child, 30 seconds and no retry or old test replay. Six candidate QML parts, four existing toolbox wrapper parts, the new test and provenance are literal-pinned. The checker is frozen externally by ROOT and preserved before/after; CMD has its own literal pin. Fourteen private source snapshots are read back. Actual MtaEmbedded selects the fixed new MtaHost through a mock app.mtaHostSource, with empty credentials and bootstrap disabled. Its real request methods do not start XHR. The action fixture derives only Page.request as delayed in-memory HTTP; actual composed QML properties, labels, gates and MouseAreas run. No HTTP service, State, transport, GATT, Wi-Fi, production admission or phone is exercised. The composed page preserves GO prepare/current-peer selection and separates receive archive download from unpack/check progress. Bytes sent are not peer completion. Confirmation/restoration and reset/leave remain UI boundaries; none issues reception, transmission or restoration permission. Qt platform=windows, software rendering, child-only DPI=1, brief actual HOST windows. Two new unedited grabWindow PNGs display HOST badges and are 800x268; dimensions, chunk CRC, SHA and saved bytes are checked. HOST Qt is not P011 Qt5.10.1 or physical display/touch. Native pure-QML launcher, complete service start, receive/send availability and phone interoperability remain unverified. Success requires child exit0, no timeout, exact marker and strict Ran1/OK with only bounded exact non-identifying Qt constants allowed. Success ZIP has result/README/strict raw/two HOST PNGs; failure ZIP only result/README and keeps original failure raw and captures privately. No private inputs or credentials enter the public ZIP. Inventory, CRC and member bytes are verified before returning success.\n".encode('ascii')
    save_new(output / 'result.json', result)
    save_new(output / 'README.txt', readme)
    members = {'result.json': result, 'README.txt': readme}
    if passed:
        members.update({'stdout.raw': stdout, 'stderr.raw': stderr})
        for name in CAPTURES:
            members[name] = images[name]
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
                    info.CRC != (zlib.crc32(raw) & 0xffffffff) or read_regular(output / name) != raw):
                raise ValueError('zip_member_changed')
    print(json.dumps(dict(passed=passed, child_exit=code, timeout=timeout,
        elapsed_seconds=elapsed, result_zip=str(archive), zip_sha256=sha(read_regular(archive)),
        zip_members_verified=True)))
    return 0 if passed else 2 if error else 1


if __name__ == '__main__':
    sys.exit(main())
