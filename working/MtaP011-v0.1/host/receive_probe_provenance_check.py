"""Only new HOST capability-provenance contracts; no ADB/native/RF."""
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
TEST = 'tests/test_receive_probe_provenance.py'
INPUTS = (TEST, 'tests/fixtures/receive_probe_fixture.py',
    'candidate/receive-probe-provenance-v1/runtime/mta_service.py',
    'runtime/p011_json.py', 'host/receive_probe_provenance_check.py',
    'HOST_MTA_RECEIVE_PROBE_PROVENANCE_CHECK.cmd')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def child():
    spec = importlib.util.spec_from_file_location('fixed_new_probe_test', str(BASE / TEST))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite = unittest.TestLoader().loadTestsFromModule(module)
    if suite.countTestCases() != 1:
        raise ValueError('new_method_count')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print('NEW_RECEIVE_PROBE_HOST methods=1 old_methods=0 device=false rf=false', flush=True)
    return 0 if result.wasSuccessful() else 1


def main():
    if sys.argv[1:] == ['--child']:
        return child()
    if sys.argv[1:]:
        raise ValueError('No device mode')
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    out = BASE / 'results' / ('receive-probe-provenance-host-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    report = dict(schema='p011-receive-probe-provenance-host-v1', passed=False,
        evidence_level='HOST_FIXTURE_CHILDREN', new_methods=1, old_methods=0,
        device_tested=False, native_helper_tested=False, rf_tested=False, phone_tested=False,
        admission=False, full_graph=False, restoration_verified=False, pending_removed=False,
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
                stderr=subprocess.PIPE, timeout=35, check=False)
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
            stdout.count(b'RECEIVE_PROBE_PROVENANCE_CONTRACTS=') == 1 and
            stdout.count(b'NEW_RECEIVE_PROBE_HOST methods=1 old_methods=0 device=false rf=false') == 1)
    except Exception as error:
        report['error'] = type(error).__name__
        (out / 'private-error.txt').write_text(str(error), encoding='utf-8')
    raw = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('ascii')
    (out / 'result.json').write_bytes(raw)
    note = b'New HOST fixture children and extracted original probe methods only. Not native helpers, device startup, RF admission, phone acceptance or restoration. No old pending handling. Private raw and source snapshots remain local.\n'
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', raw)
        archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        if archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or archive.read('result.json') != raw or archive.read('README.txt') != note:
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], result=str(out), new_methods=1,
        old_methods=0, device_tested=False, phone_tested=False), ensure_ascii=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
