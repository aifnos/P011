"""One selected new HOST method on private immutable snapshots; never ADB/RF."""
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
CONTRACTS = {
    'control': 'host/receive_durable_control_bridge_v1_host_manifest.json',
    'executor': 'host/receive_durable_executor_v1_host_manifest.json',
    'ui': 'host/receive_durable_ui_v1_host_manifest.json',
    'picker': 'host/formal_send_picker_generation_v1_host_manifest.json',
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fresh(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise ValueError('snapshot_short_write')
    if path.read_bytes() != raw:
        raise ValueError('snapshot_readback')


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in CONTRACTS:
        return 2
    name, manifest_path = sys.argv[1], CONTRACTS[sys.argv[1]]
    manifest_raw = (BASE / manifest_path).read_bytes()
    spec = json.loads(manifest_raw)
    if (set(spec) != {'schema', 'test', 'selector', 'marker', 'inputs', 'boundary'} or
            spec['schema'] != 'p011-affected-host-contract-v1' or
            not re.fullmatch(r'[A-Za-z0-9_]+\.test_[a-z0-9_]+', spec['selector']) or
            not spec['test'].startswith('tests/test_') or
            not spec['test'].endswith('.py') or type(spec['inputs']) is not list):
        raise ValueError('contract_shape')
    originals = {}
    for row in spec['inputs']:
        if (set(row) != {'path', 'bytes', 'sha256'} or type(row['path']) is not str or
                Path(row['path']).is_absolute() or '..' in Path(row['path']).parts or
                row['path'] in originals):
            raise ValueError('input_shape')
        raw = (BASE / row['path']).read_bytes()
        if (len(raw), digest(raw)) != (row['bytes'], row['sha256']):
            raise ValueError('input_pin')
        originals[row['path']] = raw
    if spec['test'] not in originals:
        raise ValueError('missing_selected_test')
    originals[manifest_path] = manifest_raw
    originals['host/receive_durable_state_v1_host_check.py'] = Path(__file__).read_bytes()
    out = BASE / 'results' / ('receive-durable-' + name + '-v1-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-inputs'
    for path, raw in originals.items():
        fresh(private / path, raw)
    target = str(private / spec['test'])
    if not target.startswith('D:\\project\\P011\\working\\MtaP011-v0.1\\results\\'):
        raise ValueError('fixed_workspace_required')
    if name in ('ui', 'picker'):
        command = [sys.executable, '-I', '-B', target, spec['selector']]
    else:
        target = '/mnt/d/' + target[3:].replace('\\', '/')
        command = ['wsl.exe', '-d', 'kali-linux', '--exec', '/usr/bin/python3',
            '-I', '-B', target, spec['selector']]
    timeout, code, stdout, stderr = False, None, b'', b''
    try:
        child = subprocess.run(command, cwd=str(private), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
        code, stdout, stderr = child.returncode, child.stdout, child.stderr
    except subprocess.TimeoutExpired as error:
        timeout, stdout, stderr = True, error.stdout or b'', error.stderr or b''
    fresh(out / 'private-raw/stdout.raw', stdout)
    fresh(out / 'private-raw/stderr.raw', stderr)
    unchanged = all((BASE / path).read_bytes() == raw and
        (private / path).read_bytes() == raw for path, raw in originals.items())
    marker = (spec['marker'] + '\n').encode('ascii')
    passed = (code == 0 and not timeout and unchanged and stdout.replace(b'\r\n', b'\n') == marker and
        re.search(rb'^Ran 1 test in [0-9.]+s\r?$', stderr, re.M) is not None and
        re.search(rb'^OK\r?$', stderr, re.M) is not None)
    report = dict(schema='p011-receive-durable-affected-host-v1', contract=name, passed=passed,
        child_exit=code, host_exit=0 if passed else 1, remote_exit='NOT_RUN_HOST_ONLY',
        timeout=timeout, child_invocations=1, methods_run=1 if passed else None,
        old_methods_requested=0, source_preserved=unchanged,
        device=False, phone=False, rf=False, deployed=False, full_graph=False,
        restoration_verified=False, real_mobile_transfer_verified=False,
        host_runtime='Windows Python312/PyQt5' if name in ('ui', 'picker') else 'WSL kali-linux python3',
        boundary=spec['boundary'], inputs=[dict(path=path, bytes=len(raw), sha256=digest(raw))
            for path, raw in originals.items()],
        streams=[dict(name=name, bytes=len(raw), sha256=digest(raw)) for name, raw in
            (('stdout.raw', stdout), ('stderr.raw', stderr))])
    members = {'result.json': (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'README.txt': ('One selected affected HOST test only; no old suite replay. ' +
            spec['boundary'] + ' No P011/phone/RF/deployment/full-graph/restoration acceptance. ' +
            'Raw streams and exact source snapshots remain private.\n').encode('ascii')}
    for path, raw in members.items():
        fresh(out / path, raw)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for path, raw in members.items():
            bundle.writestr(path, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != list(members) or bundle.testzip() is not None or any(
                bundle.read(path) != raw for path, raw in members.items()):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=passed, child_exit=code, host_exit=0 if passed else 1,
        timeout=timeout, result=str(out / 'result.json'), zip=str(archive),
        zip_sha256=digest(archive.read_bytes())), sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
