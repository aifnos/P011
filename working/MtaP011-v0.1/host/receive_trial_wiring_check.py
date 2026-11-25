"""Only three new HOST receive-trial contracts; no ADB, native helper or RF."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
TESTS = ('tests/test_receive_trial_gate.py', 'tests/test_receive_trial_state_wiring.py',
         'tests/test_receive_trial_owner_wiring.py')
INPUTS = TESTS + ('runtime/mta_receive_trial.py',
    'candidate/formal-receive-v2/runtime/mta_service.py',
    'candidate/formal-receive-v2/runtime/mta_client_service_owner.py',
    'candidate/formal-receive-v2/runtime/mta_receive_barrier.py',
    'runtime/mta_receive_radio_baseline.py', 'runtime/p011_json.py',
    'host/receive_trial_wiring_check.py', 'HOST_MTA_RECEIVE_TRIAL_WIRING_CHECK.cmd')
MARKERS = ('TRIAL_GATE_CONTRACTS', 'TRIAL_STATE_CONTRACTS', 'TRIAL_OWNER_CONTRACTS')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def selected_tests(arguments):
    if not arguments:
        return TESTS, MARKERS, 'all_new'
    for index, choice in enumerate(('--only-gate', '--only-state', '--only-owner')):
        if arguments == [choice]:
            return TESTS[index:index + 1], MARKERS[index:index + 1], choice[2:]
    raise ValueError('No device or arbitrary test mode')


def child(arguments):
    selected, markers, mode = selected_tests(arguments)
    suites = []
    for index, name in enumerate(selected):
        spec = importlib.util.spec_from_file_location('fixed_new_trial_test_' + str(index), str(BASE / name))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        suite = unittest.TestLoader().loadTestsFromModule(module)
        if suite.countTestCases() != 1:
            raise ValueError('new_method_count')
        suites.append(suite)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(suites))
    print('NEW_RECEIVE_TRIAL_HOST methods=' + str(len(selected)) +
          ' old_methods=0 device=false rf=false', flush=True)
    return 0 if result.wasSuccessful() else 1


def write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise OSError('short_write')


def main():
    arguments = sys.argv[1:]
    if arguments[:1] == ['--child']:
        return child(arguments[1:])
    selected, markers, mode = selected_tests(arguments)
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    out = BASE / 'results' / ('receive-trial-wiring-host-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    report = dict(schema='p011-receive-trial-wiring-host-v1', passed=False,
        evidence_level='HOST_CONTRACT_MODELS', new_methods=len(selected), old_methods=0, mode=mode,
        device_tested=False, native_helper_tested=False, rf_tested=False, phone_tested=False,
        admission=False, full_graph=False, restoration_verified=False, pending_removed=False,
        source_preserved=False, host_exit=None, source_count=0, error=None)
    originals = {}
    try:
        inventory = {}
        for name in INPUTS:
            raw = (BASE / name).read_bytes()
            originals[name] = raw
            snapshot = out / 'private-inputs' / name
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            write_new(snapshot, raw)
            inventory[name] = dict(bytes=len(raw), sha256=digest(raw))
        report['source_count'] = len(originals)
        write_new(out / 'private-inputs.json',
                  (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
        try:
            process = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--child'] + arguments,
                cwd=str(BASE), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=35, check=False)
            stdout, stderr = process.stdout, process.stderr
            report['host_exit'] = process.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            report['error'] = 'new_test_timeout'
        for name, raw in (('stdout', stdout), ('stderr', stderr)):
            write_new(out / (name + '.raw'), raw)
            report[name + '_bytes'] = len(raw)
            report[name + '_sha256'] = digest(raw)
        write_new(out / 'host-exit.raw', (str(report['host_exit']) + '\n').encode('ascii'))
        report['source_preserved'] = all((BASE / name).read_bytes() == raw and
            (out / 'private-inputs' / name).read_bytes() == raw for name, raw in originals.items())
        markers_valid = True
        for marker in markers:
            rows = re.findall(rb'^' + marker.encode('ascii') + rb'=([0-9]+)\r?$', stdout, re.M)
            count = int(rows[0]) if len(rows) == 1 else 0
            report[marker.lower()] = count
            markers_valid = markers_valid and len(rows) == 1 and 1 <= count <= 256
        report['passed'] = (report['host_exit'] == 0 and report['source_preserved'] and markers_valid and
            stdout.count(('NEW_RECEIVE_TRIAL_HOST methods=' + str(len(selected)) +
                          ' old_methods=0 device=false rf=false').encode('ascii')) == 1)
    except Exception as error:
        report['error'] = type(error).__name__
        write_new(out / 'private-error.txt', str(error).encode('utf-8'))
    raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    write_new(out / 'result.json', raw)
    note = (b'Three new HOST methods only: full original trial module and extracted original '
        b'State/Owner wiring. Owner, barrier, probe, Session, collection and IO fixtures are models. '
        b'No old tests, full platform graph, ADB, native RF, file receive, phone acceptance or '
        b'restoration is tested or claimed. No old pending handling. Original raw and snapshots '
        b'remain private. This result does not grant receive admission.\n')
    write_new(out / 'README.txt', note)
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', raw)
        archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        if (archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or
                archive.read('result.json') != raw or archive.read('README.txt') != note):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out), result_zip=str(bundle),
        zip_sha256=digest(bundle.read_bytes()), new_methods=len(selected), old_methods=0,
        device_tested=False, phone_tested=False), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
