"""Plain PC-only v2 focused tests, original stdout/stderr and result ZIP.

No device, source assembly, deployment or admission. --linux runs the same
fixed new tests in the existing Kali WSL Python; no package/service changes.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import zipfile

BASE = Path(__file__).resolve().parents[1]
TEST = 'tests/test_filecenter_deadline_v2.py'
METHODS = ('test_held_server_locks_return_pending_without_blocking_closed',
    'test_held_audio_lock_bounds_stop_snapshot_and_passive_close',
    'test_companion_binds_original_audio_parent_and_normal_close',
    'test_audio_pending_queries_cannot_renew_failed_cleanup',
    'test_reader_constructor_failure_cannot_renew_parent_deadline',
    'test_started_reader_exception_cannot_renew_parent_deadline',
    'test_new_sources_parse_python35_and_owner_pins_match')
INPUTS = tuple('candidate/filecenter-deadline-v2/runtime/'+name+'.py'
    for name in ('mta_filecenter_audio', 'mta_filecenter_companion', 'mta_client_service_owner')) + (
    TEST, 'host/filecenter_deadline_v2_check.py', 'HOST_MTA_FILECENTER_DEADLINE_V2_CHECK.cmd')


def digest(raw): return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linux', action='store_true')
    parser.add_argument('--only', choices=METHODS, nargs='+')
    args = parser.parse_args()
    methods = args.only or list(METHODS)
    selected = ['FileCenterDeadlineV2Tests.'+name for name in methods]
    command = ([str(Path(sys.executable)), str(BASE/TEST)] + selected if not args.linux else
        ['wsl.exe', '-d', 'kali-linux', '--', 'python3', '/mnt/d/project/P011/working/MtaP011-v0.1/'+TEST] + selected)
    out = BASE/'results'/('filecenter-deadline-v2-'+('linux' if args.linux else 'windows')+'-'+
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    originals = {name:(BASE/name).read_bytes() for name in INPUTS}
    source_info = {name:dict(bytes=len(raw), sha256=digest(raw)) for name, raw in originals.items()}
    stdout, stderr, code, error = b'', b'', 'NOT_RUN', None
    try:
        completed = subprocess.run(command, cwd=str(BASE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        stdout, stderr, code = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as failure:
        stdout, stderr, code, error = failure.stdout or b'', failure.stderr or b'', 'TIMEOUT', 'TimeoutExpired'
    except Exception as failure: error = type(failure).__name__
    unchanged = all((BASE/name).read_bytes()==raw for name, raw in originals.items())
    report = dict(scope='PC_ONLY_v2_affected_tests', platform='WSL_kali_linux' if args.linux else sys.platform,
        tests=selected, host_exit=code, host_error=error, source_unchanged=unchanged,
        passed=code==0 and error is None and unchanged, stdout_bytes=len(stdout), stdout_sha256=digest(stdout),
        stderr_bytes=len(stderr), stderr_sha256=digest(stderr),
        process_timeout_seconds=20, old_v1_tests_replayed=False, adb=False, device=False,
        original_owner_graph=False, guardian=False, physical_audio=False, restoration=False,
        boundary='Actual PC locks, threads, HTTP and POSIX children; gst argv and Thread failure fixtures are HOST models.')
    outputs = {'stdout.raw':stdout, 'stderr.raw':stderr,
        'result.json':(json.dumps(report, sort_keys=True, indent=2)+'\n').encode('utf-8'),
        'source-sha256.json':(json.dumps(source_info, sort_keys=True, indent=2)+'\n').encode('utf-8')}
    for name, raw in outputs.items():
        with (out/name).open('xb') as stream: stream.write(raw)
    archive = out/'PC_RESULTS.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in outputs.items(): bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        if set(bundle.namelist()) != set(outputs) or any(bundle.read(name)!=raw for name, raw in outputs.items()):
            raise ValueError('result_zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out), zip=str(archive),
        zip_sha256=digest(archive.read_bytes()), host_exit=code), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__=='__main__': raise SystemExit(main())
