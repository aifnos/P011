"""Fixed new HOST UI-inventory method, with raw logs and private snapshots."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
TEST = 'tests/test_receive_ui_inventory.py'
INPUTS = (TEST, 'candidate/formal-receive-v3/runtime/mta_formal_receive_session.py',
          'host/receive_ui_inventory_check.py', 'HOST_MTA_RECEIVE_UI_INVENTORY_CHECK.cmd')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise OSError('short_write')


def main():
    if sys.argv[1:]:
        raise ValueError('fixed HOST method only')
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    out = BASE / 'results' / ('receive-ui-inventory-host-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    report = dict(schema='p011-receive-ui-inventory-host-v1', passed=False,
        host_exit=None, error=None, new_methods=1, old_methods=0,
        device_tested=False, qt_tested=False, rf_tested=False, phone_tested=False,
        restoration_verified=False, pending_handled=False, source_preserved=False,
        evidence_level='HOST_EXTRACTED_METHOD_AND_CONTROL_MODELS')
    originals = {}
    try:
        inventory = {}
        for name in INPUTS:
            raw = (BASE / name).read_bytes()
            originals[name] = raw
            save(out / 'private-inputs' / name, raw)
            inventory[name] = dict(bytes=len(raw), sha256=digest(raw))
        save(out / 'private-inputs.json', (json.dumps(inventory, indent=2, sort_keys=True) + '\n').encode('ascii'))
        try:
            process = subprocess.run([sys.executable, '-I', '-B', str(BASE / TEST)],
                cwd=str(BASE), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=35, check=False)
            stdout, stderr = process.stdout, process.stderr
            report['host_exit'] = process.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            report['error'] = 'new_method_timeout'
        for name, raw in (('stdout', stdout), ('stderr', stderr)):
            save(out / (name + '.raw'), raw)
            report[name + '_bytes'] = len(raw)
            report[name + '_sha256'] = digest(raw)
        save(out / 'host-exit.raw', (str(report['host_exit']) + '\n').encode('ascii'))
        report['source_count'] = len(originals)
        report['source_preserved'] = all((BASE / name).read_bytes() == raw and
            (out / 'private-inputs' / name).read_bytes() == raw for name, raw in originals.items())
        markers = re.findall(rb'^RECEIVE_UI_INVENTORY_CONTRACTS=([0-9]+)\r?$', stdout, re.M)
        report['inventory_contracts'] = int(markers[0]) if len(markers) == 1 else 0
        report['passed'] = (report['host_exit'] == 0 and report['error'] is None and
            report['source_preserved'] and report['inventory_contracts'] == 21 and
            re.search(rb'^Ran 1 test in [0-9.]+s\r?$', stderr, re.M) is not None and
            re.search(rb'^OK\r?$', stderr, re.M) is not None)
    except Exception as error:
        report['error'] = type(error).__name__
        save(out / 'private-error.txt', str(error).encode('utf-8'))
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'One new HOST UI empty-inventory method and load_owner AST wiring. '
        b'Actual runner methods are extracted; State/Gate/Owner bindings are explicit models. '
        b'An empty original inventory is not a closed receive admission or restoration receipt. '
        b'No Qt, ADB, RF, phone, original FD closure or receive/restore acceptance. '
        b'No old tests or pending record handling. Raw logs and input snapshots stay private.\n')
    save(out / 'result.json', public)
    save(out / 'README.txt', note)
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', public)
        archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        if archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or \
                archive.read('result.json') != public or archive.read('README.txt') != note:
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out), result_zip=str(bundle),
        zip_bytes=bundle.stat().st_size, zip_sha256=digest(bundle.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
