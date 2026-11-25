"""One-click HOST checks for the new receive network consumer and UI monitor.

No ADB/WSL/Docker, device, native helper, RF, phone, admission or restore.
Observation, Session and UI scopes are explicit HOST models, not device proof.
Only new tests execute; old test methods are neither loaded nor replayed.
"""
import ast
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
TESTS = ('test_receive_network_observer', 'test_receive_network_consumer', 'test_formal_ui_receive_monitor_v1')
NEW_SOURCES = ('candidate/receive-network-consumer-v1/runtime/mta_service.py',
    'candidate/formal-ui-receive-monitor-v1/runtime/receive_monitor.py')
INPUTS = NEW_SOURCES + (
    'runtime/mta_receive_network.py',
    'candidate/receive-network-observer-v1/native/mta_connman_observer.c',
    'runtime/p011_json.py',
    'host/client_receive_startup_readonly_v4_definition_manifest.json',
    'host/client_receive_startup_readonly_v4_private_source_manifest.json',
    'tests/test_receive_network_observer.py', 'tests/test_receive_network_consumer.py',
    'tests/test_formal_ui_receive_monitor_v1.py', 'host/device_receive_network_observer_check.py',
    'host/build_receive_network_observer.py',
    'host/receive_network_integration_check.py', 'HOST_MTA_RECEIVE_NETWORK_INTEGRATION_CHECK.cmd')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def child():
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for name in TESTS:
        spec = importlib.util.spec_from_file_location(name, str(BASE / 'tests' / (name + '.py')))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        suite.addTests(loader.loadTestsFromModule(module))
    count = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print('NEW_RECEIVE_NETWORK_HOST tests=%d old_methods=0 device=false rf=false' % count)
    return 0 if result.wasSuccessful() else 1


def main():
    if sys.argv[1:] == ['--child']:
        return child()
    if sys.argv[1:]:
        raise ValueError('No device or mutation mode')
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    out = BASE / 'results' / ('receive-network-integration-host-' + stamp)
    out.mkdir(parents=True)
    report = {'evidence_level': 'HOST_ONLY', 'passed': False,
        'python35_ast': False, 'new_tests_only': True, 'source_preserved': False,
        'device_tested': False, 'native_helper_executed': False, 'rf_tested': False,
        'phone_tested': False, 'receive_admission': False, 'restoration_verified': False,
        'pending_removed': False, 'inputs': [], 'host_exit': None, 'error': None}
    originals = {}
    try:
        paths = set(INPUTS)
        # Snapshot dependencies actually used by the fixture loader; this is
        # source retention, not execution or repeated testing of those modules.
        for manifest in ('host/client_receive_startup_readonly_v4_definition_manifest.json',
                         'host/client_receive_startup_readonly_v4_private_source_manifest.json'):
            table = json.loads((BASE / manifest).read_text(encoding='utf-8'))
            rows = table.get('definitions', table.get('modules', table.get('sources', [])))
            if isinstance(rows, dict):
                rows = list(rows.values())
            for row in rows:
                if isinstance(row, dict) and isinstance(row.get('path'), str):
                    paths.add(row['path'])
        for name in sorted(paths):
            raw = (BASE / name).read_bytes()
            originals[name] = raw
            target = out / 'private-inputs' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            report['inputs'].append({'path': name, 'bytes': len(raw), 'sha256': digest(raw)})
        for name in NEW_SOURCES:
            ast.parse(originals[name].decode('utf-8'), filename=name, feature_version=(3, 5))
        report['python35_ast'] = True
        try:
            process = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--child'],
                cwd=str(BASE), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=60, check=False)
            stdout, stderr = process.stdout, process.stderr
            report['host_exit'] = process.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            report['error'] = 'host_tests_timeout'
        (out / 'stdout.raw').write_bytes(stdout)
        (out / 'stderr.raw').write_bytes(stderr)
        (out / 'host-exit.raw').write_bytes(str(report['host_exit']).encode('ascii') + b'\n')
        for name, raw in (('stdout', stdout), ('stderr', stderr)):
            report[name] = {'bytes': len(raw), 'sha256': digest(raw)}
        report['source_preserved'] = all((BASE / name).read_bytes() == raw for name, raw in originals.items())
        report['passed'] = (report['host_exit'] == 0 and report['source_preserved'] and
            stdout.count(b'NEW_RECEIVE_NETWORK_HOST ') == 1)
    except Exception as error:
        report['error'] = type(error).__name__
        (out / 'host-error-private.txt').write_text(str(error), encoding='utf-8')
    (out / 'result.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    (out / 'README.txt').write_text(
        'HOST-only new network consumer and UI monitor tests. Python 3.5 AST for two unexecuted sources.\n'
        'Original observation and Session/UI scopes here are explicit HOST models, not P011.\n'
        'No ADB, radio, phone, gate opening, pending cleanup or restoration proof.\n'
        'Raw output and exact input snapshots remain private and failures are retained.\n', encoding='utf-8')
    with zipfile.ZipFile(out / 'public-result.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for name in ('result.json', 'README.txt'):
            archive.write(out / name, name)
    print(json.dumps(report, ensure_ascii=False))
    print('RESULT_DIR=' + str(out))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
