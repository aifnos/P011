"""One fixed affected Linux contract, original outputs and evidence ZIP.

PC only. No ADB, deployment, RF, service changes or old tests. Requires the
author's final frozen v2 handoff; records actual native FD/semaphore checks,
not P011 ABI or complete service restoration.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import zipfile

BASE = Path(__file__).resolve().parents[1]
FREEZE = 'candidate/formal-send-filecenter-ui-v7/FROZEN-PC-HANDOFF-v2.json'
TEST = 'tests/test_formal_socket_close_v5_linux.py'
METHOD = 'SocketCloseV5Contract.test_real_fd_reuse_original_receipt_and_http_finally'
INPUTS = (TEST, 'candidate/formal-send-filecenter-deploy-v5/runtime/mta_client_service_owner.py',
          'candidate/formal-send-filecenter-deploy-v5/runtime/minhttp.py')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-linux', action='store_true')
    args = parser.parse_args()
    if not args.run_linux:
        print('PC_SOURCE_ONLY; contract_not_invoked; no_device')
        return 0
    frozen = json.loads((BASE / FREEZE).read_bytes())
    original = {name: (BASE / name).read_bytes() for name in INPUTS}
    pins = {row['path']: (row['bytes'], row['sha256']) for row in frozen['files']}
    if not frozen['frozen'] or any((len(raw), digest(raw)) != pins.get(name)
                                  for name, raw in original.items()):
        raise ValueError('frozen_contract_inputs_changed')
    out = BASE / 'results' / ('formal-socket-close-v5-linux-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    command = ['wsl.exe', '-d', 'kali-linux', '--', 'python3', '-I', '-B',
               '/mnt/d/project/P011/working/MtaP011-v0.1/' + TEST, METHOD, '-v']
    stdout, stderr, code, error = b'', b'', 'NOT_RUN', None
    try:
        value = subprocess.run(command, cwd=str(BASE), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=30)
        stdout, stderr, code = value.stdout, value.stderr, value.returncode
    except subprocess.TimeoutExpired as failure:
        stdout, stderr, code, error = failure.stdout or b'', failure.stderr or b'', 'TIMEOUT', 'TimeoutExpired'
    except Exception as failure:
        error = type(failure).__name__
    unchanged = all((BASE / name).read_bytes() == raw for name, raw in original.items())
    report = dict(scope='one_affected_Linux_contract', platform='WSL_kali_linux',
        selected_method=METHOD, host_exit=code, host_error=error, source_unchanged=unchanged,
        passed=code == 0 and error is None and unchanged, timeout_seconds=30,
        stdout_bytes=len(stdout), stderr_bytes=len(stderr), adb=False, device=False,
        old_tests_run=0, full_owner_closure=False, phone_interop=False)
    outputs = {'stdout.raw': stdout, 'stderr.raw': stderr,
        'result.json': (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'source-sha256.json': (json.dumps({name: dict(bytes=len(raw), sha256=digest(raw))
            for name, raw in original.items()}, sort_keys=True, indent=2) + '\n').encode('ascii')}
    for name, raw in outputs.items():
        with (out / name).open('xb') as stream:
            stream.write(raw)
    archive = out / 'PC_RESULTS.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in outputs.items():
            bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        if set(bundle.namelist()) != set(outputs) or bundle.testzip() is not None or any(
                bundle.read(name) != raw for name, raw in outputs.items()):
            raise ValueError('evidence_zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        zip_sha256=digest(archive.read_bytes()), host_exit=code), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
