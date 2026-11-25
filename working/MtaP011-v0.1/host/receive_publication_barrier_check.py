"""One-click new readonly publication Barrier HOST models only; no ADB or RF.

All Owner/IO/FD/flags inventories are HOST models, not device publication or restoration.
Old consumer/monitor/HTTP test methods are not replayed.
"""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
TEST = 'tests/test_receive_publication_barrier.py'
INPUTS = (TEST, 'candidate/receive-publication-barrier-v1/runtime/receive_barrier.py',
    'host/receive_publication_barrier_check.py', 'HOST_MTA_RECEIVE_PUBLICATION_BARRIER_CHECK.cmd')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def child():
    spec = importlib.util.spec_from_file_location('fixed_new_publication_barrier_test', str(BASE / TEST))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite = unittest.TestLoader().loadTestsFromModule(module)
    if suite.countTestCases() != 1:
        raise ValueError('new_method_count')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print('NEW_RECEIVE_PUBLICATION_BARRIER_HOST methods=1 cases=26 old_methods=0 device=false rf=false', flush=True)
    return 0 if result.wasSuccessful() else 1


def main():
    if sys.argv[1:] == ['--child']:
        return child()
    if sys.argv[1:]:
        raise ValueError('No device mode')
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    out = BASE / 'results' / ('receive-publication-barrier-host-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    report = dict(schema='p011-receive-publication-barrier-host-v1', passed=False,
        evidence_level='HOST_SCOPE_MODELS', new_methods=1, new_subcases=26, old_methods=0,
        device_tested=False, rf_tested=False, phone_tested=False, admission=False,
        full_graph=False, restoration_verified=False, pending_removed=False,
        source_preserved=False, host_exit=None, inputs=[], error=None)
    originals = {}
    try:
        for name in INPUTS:
            raw = (BASE / name).read_bytes()
            originals[name] = raw
            snapshot = out / 'private-inputs' / name
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            snapshot.write_bytes(raw)
            report['inputs'].append(dict(path=name, bytes=len(raw), sha256=digest(raw)))
        try:
            process = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--child'],
                cwd=str(BASE), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=30, check=False)
            stdout, stderr = process.stdout, process.stderr
            report['host_exit'] = process.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            report['error'] = 'new_test_timeout'
        for name, raw in (('stdout', stdout), ('stderr', stderr)):
            (out / (name + '.raw')).write_bytes(raw)
            report[name] = dict(bytes=len(raw), sha256=digest(raw))
        (out / 'host-exit.raw').write_bytes((str(report['host_exit']) + '\n').encode('ascii'))
        report['source_preserved'] = all((BASE / name).read_bytes() == raw for name, raw in originals.items())
        report['passed'] = (report['host_exit'] == 0 and report['source_preserved'] and
            stdout.count(b'RECEIVE_PUBLICATION_BARRIER_MODELS=') == 1 and
            stdout.count(b'NEW_RECEIVE_PUBLICATION_BARRIER_HOST methods=1 cases=26 old_methods=0 device=false rf=false') == 1)
    except Exception as error:
        report['error'] = type(error).__name__
        (out / 'private-error.txt').write_text(str(error), encoding='utf-8')
    raw = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('ascii')
    (out / 'result.json').write_bytes(raw)
    note = b'New HOST publication Barrier Owner/IO/FD/flags models only. No device, RF, phone, admission, old pending handling or restoration proof. Private raw and source snapshots remain local.\n'
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', raw)
        archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        if archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or archive.read('result.json') != raw or archive.read('README.txt') != note:
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], result=str(out), new_methods=1,
        new_subcases=26, old_methods=0, device_tested=False, phone_tested=False), ensure_ascii=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

