"""Focused HOST audio callback-cap checks; SOURCE by default, --run explicit.

Run only the eight new methods in the fixed WSL Linux test source. Its private
Companion/guard and stopped-wrapper/guardian/reader doubles are not native
Owner, device, playback or phone evidence. No Docker, ADB or old suite runs.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/filecenter_audio_source_cap_v1_check.py'
CMD = 'HOST_MTA_FILECENTER_AUDIO_SOURCE_CAP_V1_CHECK.cmd'
TEST = 'tests/test_filecenter_audio_source_cap_v1.py'
SOURCES = (
    SELF, CMD, TEST,
    'candidate/filecenter-audio-source-cap-v1/shared/mta_filecenter_audio.py',
    'candidate/filecenter-audio-source-cap-v1/send/mta_filecenter_companion.py',
    'candidate/filecenter-audio-source-cap-v1/receive/mta_filecenter_companion.py',
    'candidate/filecenter-deadline-v2/runtime/mta_filecenter_audio.py',
    'candidate/filecenter-media-lock-deadline-v1/send/mta_filecenter_companion.py',
    'candidate/filecenter-media-lock-deadline-v1/receive/mta_filecenter_companion.py',
    'integration/ToolboxMta-v0.1/runtime/mta_toolbox_json.py',
    'candidate/filecenter-http-parent-cap-v1/shared/mta_toolbox_minhttp.py',
    'integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py',
    'integration/ToolboxMta-v0.1/runtime/mta_toolbox_metrics.py',
    'integration/ToolboxMta-v0.1/runtime/mta_toolbox_audio.py',
    'integration/ToolboxMta-v0.1/runtime/mta_toolbox_server.py',
    'candidate/receive-filecenter-v1/runtime/mta_filecenter_storage.py',
    'candidate/filecenter-close-seal-v1/runtime/mta_filecenter_storage.py',
)
METHODS = frozenset((
    'test_new_sources_python35_and_exact_byte_inverse',
    'test_legacy_one_argument_and_no_typeerror_signature_guess',
    'test_sealed_callback_identity_before_and_after_lookup',
    'test_play_both_source_lookups_share_absolute_cap_and_fd_check',
    'test_expired_callback_return_before_spawn_and_after_guardian_never_resumes',
    'test_guardian_cannot_replace_both_visible_and_retained_callback',
    'test_actual_companion_callback_lock_obeys_short_cap_in_both_families',
    'test_original_close_cancels_waiting_callback_without_releasing_holder',
))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw): raise ValueError('short_write')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    mode = 'host' if args.run else 'source'
    out = BASE/'results'/('filecenter-audio-source-cap-v1-'+mode+'-'+
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out/'private'; private.mkdir()
    inputs = {}
    report = dict(mode=mode, passed=False, source_checked=False, source_preserved=False,
        input_count=0, source_pins={}, tests_run=0, expected_test_methods=8,
        child_invoked=False, child_exit=None, child_timeout=False, error=None,
        private_companion_guard_fixture=True, process_guardian_reader_doubles=True,
        native_owner_verified=False, actual_playback=False, device=False, rf=False,
        phone=False, package_assembled=False, full_restoration=False, old_tests_run=0)
    try:
        for path in SOURCES:
            raw = (BASE/path).read_bytes(); inputs[path] = raw
            write_new(private/'inputs'/path, raw)
            if path.endswith('.py'): ast.parse(raw)
        test_tree = ast.parse(inputs[TEST])
        classes = [node for node in test_tree.body if isinstance(node, ast.ClassDef)
                   and node.name == 'AudioSourceCapTests']
        if len(classes) != 1 or {node.name for node in classes[0].body
                if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')} != METHODS:
            raise ValueError('new_method_inventory')
        for path in SOURCES[3:6]: ast.parse(inputs[path], feature_version=(3, 5))
        report['source_checked'] = True
        if args.run:
            # Direct argv: no shell, source injection, arbitrary command or
            # unrelated distribution. -I/-B apply to the actual Linux child.
            command = ['wsl.exe', '-d', 'kali-linux', '--exec', '/usr/bin/python3',
                '-I', '-B', '/mnt/d/project/P011/working/MtaP011-v0.1/'+TEST]
            report['child_invoked'] = True
            stdout, stderr = b'', b''
            try:
                child = subprocess.run(command, cwd=BASE, capture_output=True, timeout=60)
                stdout, stderr = child.stdout, child.stderr
                report['child_exit'] = child.returncode
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b'', error.stderr or b''
                report['child_timeout'] = True
                raise
            finally:
                write_new(private/'stdout.raw', stdout)
                write_new(private/'stderr.raw', stderr)
                write_new(private/'child-exit.txt',
                    (str(report['child_exit'])+'\n').encode('ascii'))
            text = stderr.decode('utf-8', 'strict').replace('\r\n', '\n')
            counts = re.findall(r'^Ran (\d+) tests in [0-9.]+s$', text, re.M)
            completed = re.findall(r'^OK$', text, re.M)
            if (child.returncode != 0 or counts != ['8'] or completed != ['OK'] or
                    'skipped' in text.lower() or 'FAIL' in text or 'ERROR' in text):
                raise ValueError('new_host_tests_failed')
            report['tests_run'] = 8
    except Exception as error:
        report['error'] = type(error).__name__
        write_new(private/'error.txt', (repr(error)+'\n').encode('utf-8'))
    finally:
        report['input_count'] = len(inputs)
        report['source_pins'] = {path:dict(bytes=len(raw), sha256=digest(raw))
                                 for path, raw in inputs.items()}
        report['source_preserved'] = len(inputs) == len(SOURCES) and all(
            (BASE/path).read_bytes() == raw and (private/'inputs'/path).read_bytes() == raw
            for path, raw in inputs.items())
    report['passed'] = report['source_checked'] and report['source_preserved'] and report['error'] is None
    result = (json.dumps(report, sort_keys=True, indent=2)+'\n').encode('ascii')
    readme = (b'Focused new audio callback deadline HOST checks. SOURCE is default.\n'
        b'Explicit --run uses fixed Kali WSL Python; no Docker, ADB or old suite.\n'
        b'Real locks/threads/POSIX storage; private Companion/root/guard fixture.\n'
        b'Audio Popen, guardian ACK and reader are doubles; no audio process or signal.\n'
        b'Not actual Owner/P011/phone/playback or assembled package acceptance.\n'
        b'Raw streams, child exit and source snapshots are private.\n')
    write_new(out/'result.json', result); write_new(out/'README.txt', readme)
    with zipfile.ZipFile(out/'public-result.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result); archive.writestr('README.txt', readme)
    with zipfile.ZipFile(out/'public-result.zip') as archive:
        if (archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or
                archive.read('result.json') != result or archive.read('README.txt') != readme):
            raise ValueError('result_zip')
    code = 0 if report['passed'] else 1
    write_new(out/'checker-exit.txt', (str(code)+'\n').encode('ascii'))
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out),
        child_exit=report['child_exit'], child_timeout=report['child_timeout'], error=report['error'])))
    return code


if __name__ == '__main__': raise SystemExit(main())
