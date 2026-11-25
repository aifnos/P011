"""One affected PC contract with original stdout/stderr; no ADB or old tests."""
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
TEST = 'tests/test_receive_alias_clock_v1.py'
INPUTS = (TEST,
    'candidate/formal-receive-alias-clock-v1/runtime/mta_client_receive_factory.py',
    'candidate/formal-receive-alias-clock-v1/runtime/mta_client_executor.py')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-host', action='store_true')
    args = parser.parse_args()
    if not args.run_host:
        print('PC_SOURCE_ONLY; contract_not_invoked; no_device')
        return 0
    originals = {name: (BASE / name).read_bytes() for name in INPUTS}
    out = BASE / 'results' / ('receive-alias-clock-v1-contract-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    value = subprocess.run([sys.executable, '-I', '-B', str(BASE / TEST)],
        cwd=str(BASE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    unchanged = all((BASE / name).read_bytes() == raw for name, raw in originals.items())
    report = dict(kind='one_affected_HOST_contract', passed=value.returncode == 0 and unchanged,
        host_exit=value.returncode, source_unchanged=unchanged, old_tests_run=0,
        adb=False, device=False, rf=False, phone=False, performance_measured=False)
    outputs = {'stdout.raw': value.stdout, 'stderr.raw': value.stderr,
        'result.json': (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'source-sha256.json': (json.dumps({name: dict(bytes=len(raw), sha256=sha(raw))
            for name, raw in originals.items()}, sort_keys=True, indent=2) + '\n').encode('ascii')}
    for name, raw in outputs.items():
        with (out / name).open('xb') as stream:
            stream.write(raw)
    archive = out / 'PC_RESULTS.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in outputs.items():
            bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None or any(bundle.read(name) != raw for name, raw in outputs.items()):
            raise ValueError('result_zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        zip_sha256=sha(archive.read_bytes()), host_exit=value.returncode), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
