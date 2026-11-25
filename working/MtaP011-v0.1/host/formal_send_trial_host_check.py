"""Run only the new HOST SendTrial phase method; keep immutable original IO."""
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
TEST = 'tests/test_formal_send_trial.py'
INPUTS = (TEST, 'host/formal_send_trial_host_check.py', 'HOST_MTA_FORMAL_SEND_TRIAL_CHECK.cmd',
    'candidate/formal-send-v1/runtime/mta_send_trial.py',
    'candidate/go-send-state-v78/runtime/mta_transfer_session.py')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise OSError('short_write')
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw:
        raise ValueError('snapshot_readback')


def main():
    if sys.argv[1:]:
        raise ValueError('fixed_HOST_only')
    out = BASE / 'results' / ('formal-send-trial-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    sources = {}
    report = dict(schema='p011-formal-send-trial-host-v1', passed=False,
        host_exit=None, remote_exit=None, new_methods=1, old_methods=0,
        actual_gate=True, actual_session_constructor=True, actual_host_mutex=True,
        original_owner_model=True, original_state_model=True, parent_packet_ledger_model=True,
        native_assets_model=True, actual_parent=False, actual_startup=False,
        actual_session_worker=False, actual_session_finalizer=False,
        native_startup_verified=False, device=False, phone=False, restoration_verified=False,
        production_admitted=False, error=None)
    stdout = stderr = b''
    try:
        inventory = {}
        for name in INPUTS:
            raw = (BASE / name).read_bytes()
            sources[name] = raw
            save(out / 'private-inputs' / name, raw)
            inventory[name] = dict(bytes=len(raw), sha256=digest(raw))
        save(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
        try:
            child = subprocess.run([sys.executable, '-I', '-B', str(out / 'private-inputs' / TEST)],
                cwd=str(out / 'private-inputs'), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25, check=False)
            stdout, stderr = child.stdout, child.stderr
            report['host_exit'] = child.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            report['error'] = 'timeout'
        for name, raw in (('stdout', stdout), ('stderr', stderr)):
            save(out / (name + '.raw'), raw)
            report[name + '_bytes'] = len(raw)
            report[name + '_sha256'] = digest(raw)
        save(out / 'host-exit.raw', (str(report['host_exit']) + '\n').encode('ascii'))
        save(out / 'remote-exit.raw', b'NOT_RUN_HOST_ONLY\n')
        report['source_count'] = len(sources)
        report['source_preserved'] = all((BASE / name).read_bytes() == raw and
            (out / 'private-inputs' / name).read_bytes() == raw for name, raw in sources.items())
        marks = re.findall(rb'^FORMAL_SEND_TRIAL_CONTRACTS=([0-9]+)\r?$', stdout, re.M)
        report['contracts'] = int(marks[0]) if len(marks) == 1 else 0
        cases = re.findall(rb'^HOST_SEND_TRIAL_CASE=([a-z0-9_]+)\r?$', stdout, re.M)
        report['case_count'] = len(cases)
        report['passed'] = (report['host_exit'] == 0 and report['error'] is None and
            report['source_preserved'] and report['contracts'] == 18 and len(cases) == 18 and
            len(set(cases)) == 18 and re.search(rb'^Ran 1 test in [0-9.]+s\r?$', stderr, re.M) is not None and
            re.search(rb'^OK\r?$', stderr, re.M) is not None)
    except Exception as error:
        report['error'] = type(error).__name__
        save(out / 'private-error.txt', str(error).encode('utf-8'))
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'One new HOST method / 18 cases runs actual fixed SendTrial and actual '
        b'unstarted Session78 constructor with real Python mutex/Event/thread objects. '
        b'Owner, State, readonly Parent/packet/EOF/wait ledgers and native assets are explicit '
        b'models. Target module names and paths are fixtures, not deployed source authority. '
        b'No actual Parent, startup collector, Session worker/finalizer, Native, RF, UI, '
        b'P011, phone, send or restoration runs. Claim is preparation only; production '
        b'and restoration remain false. No historical method is replayed. '
        b'Raw IO and source snapshots stay PRIVATE; public ZIP has only scalar result '
        b'and this fixed README.\n')
    save(out / 'result.json', result)
    save(out / 'README.txt', note)
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result)
        archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        if (archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or
                archive.read('result.json') != result or archive.read('README.txt') != note):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        zip_bytes=bundle.stat().st_size, zip_sha256=digest(bundle.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
