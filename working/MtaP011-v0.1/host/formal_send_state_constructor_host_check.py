"""Only new HOST State constructor method; immutable originals, no device."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
TEST = 'tests/test_formal_send_state_constructor.py'
INPUTS = (TEST, 'host/formal_send_state_constructor_host_check.py',
    'HOST_MTA_FORMAL_SEND_STATE_CONSTRUCTOR_CHECK.cmd',
    'candidate/formal-send-v1/runtime/mta_service.py',
    'candidate/go-send-state-v78/runtime/mta_transfer_session.py')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw): raise OSError('short_write')
        stream.flush(); os.fsync(stream.fileno())
    if path.read_bytes() != raw: raise ValueError('snapshot_readback')


def main():
    if sys.argv[1:]: raise ValueError('fixed_HOST_only')
    out = BASE / 'results' / ('formal-send-state-constructor-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    sources, stdout, stderr = {}, b'', b''
    report = dict(schema='p011-formal-send-state-constructor-host-v1', passed=False,
        host_exit=None, remote_exit=None, new_methods=1, old_methods=0,
        actual_selected_state_methods=True, actual_operation_constructor=True,
        actual_unstarted_session_constructor=True, actual_host_mutex_event_threads=True,
        trial_model=True, callbacks_model=True, previous_session_closure_model=True,
        allocation_failure_model=True, worker_start_resolution_model=True,
        terminal_dependencies_model=True, terminal_worker_identity_model=True,
        whole_state_constructor=False, actual_send_trial=False,
        actual_session_worker=False, actual_session_finalizer=False,
        actual_owner=False, actual_parent=False, native=False, device=False, phone=False,
        send_verified=False, restoration_verified=False, production_admitted=False, error=None)
    try:
        inventory = {}
        for name in INPUTS:
            raw = (BASE / name).read_bytes(); sources[name] = raw
            save(out / 'private-inputs' / name, raw)
            inventory[name] = dict(bytes=len(raw), sha256=digest(raw))
        save(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
        try:
            child = subprocess.run([sys.executable, '-I', '-B', str(out / 'private-inputs' / TEST)],
                cwd=str(out / 'private-inputs'), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25, check=False)
            stdout, stderr = child.stdout, child.stderr; report['host_exit'] = child.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''; report['error'] = 'timeout'
        for name, raw in (('stdout', stdout), ('stderr', stderr)):
            save(out / (name + '.raw'), raw)
            report[name + '_bytes'], report[name + '_sha256'] = len(raw), digest(raw)
        save(out / 'host-exit.raw', (str(report['host_exit']) + '\n').encode('ascii'))
        save(out / 'remote-exit.raw', b'NOT_RUN_HOST_ONLY\n')
        report['source_count'] = len(sources)
        report['source_preserved'] = all((BASE / name).read_bytes() == raw and
            (out / 'private-inputs' / name).read_bytes() == raw for name, raw in sources.items())
        marks = re.findall(rb'^FORMAL_SEND_STATE_CONSTRUCTOR_CONTRACTS=([0-9]+)\r?$', stdout, re.M)
        cases = re.findall(rb'^HOST_SEND_STATE_CONSTRUCTOR_CASE=([a-z0-9_]+)\r?$', stdout, re.M)
        report['contracts'] = int(marks[0]) if len(marks) == 1 else 0
        report['case_count'] = len(cases)
        report['passed'] = (report['host_exit'] == 0 and report['error'] is None and
            report['source_preserved'] and report['contracts'] == 16 and len(cases) == 16 and
            len(set(cases)) == 16 and re.search(rb'^Ran 1 test in [0-9.]+s\r?$', stderr, re.M) is not None and
            re.search(rb'^OK\r?$', stderr, re.M) is not None)
    except Exception as error:
        report['error'] = type(error).__name__
        save(out / 'private-error.txt', str(error).encode('utf-8'))
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'One new HOST method / 16 cases executes selected actual State methods and '
        b'Operation constructor plus the original unstarted Session78 constructor. '
        b'Python locks, Event and unstarted threads are real HOST objects. Trial decisions, '
        b'callbacks, allocation failure, prior-session closure, worker-start resolution and '
        b'terminal dependencies/worker identity are explicit models. The actual final deadline '
        b'check and completion/refusal methods run, not the actual Native proofs they consume. '
        b'No whole State constructor, actual SendTrial, original Owner/Parent, '
        b'Session worker/finalizer, Native, target IO, RF, UI, P011, phone, send or restoration runs. '
        b'No historical method is replayed. Raw logs and source snapshots stay PRIVATE.\n')
    save(out / 'result.json', result); save(out / 'README.txt', note)
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result); archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        if (archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or
                archive.read('result.json') != result or archive.read('README.txt') != note):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        zip_bytes=bundle.stat().st_size, zip_sha256=digest(bundle.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
