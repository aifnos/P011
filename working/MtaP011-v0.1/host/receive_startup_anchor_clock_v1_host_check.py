"""One fixed affected HOST method, private raw bytes and public scalar ZIP."""
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
TEST = 'tests/test_receive_startup_anchor_clock_v1.py'
SELECTOR = ('ReceiveStartupAnchorClockV1Contract.'
            'test_actual_startup_anchor_density_io_and_refusals')
PINS = (
    (TEST, 23024, '8ffaa5a6cc44322ecd471b93fe1f5ca61939cee173810113cc43b0625b7eaf45'),
    ('candidate/receive-startup-anchor-clock-v1/runtime/mta_client_receive_factory.py',
     91907, 'bd6e8f65ad03bf1e18594979af21699dd97813502c4f5b6211eb6b05f026fcf5'),
    ('candidate/formal-receive-startup-boundary-timing-v1/runtime/mta_client_receive_factory.py',
     89982, 'd1637a6ba8f1d694cf240d09c62afa583dc02c07dc4dd79b4216f2643d7d5824'),
    ('candidate/receive-startup-anchor-clock-v1/exactsource-delta.json',
     5343, '23187b91b1aa63f851ac6b1e31517accaf197bc55b15d19350d6e896ef6eaaf5'),
    ('candidate/formal-receive-startup-boundary-timing-v1/runtime/mta_client_executor.py',
     117760, 'ff13becc37e9dd2d616733dd4b2381f4c968913a1d913183b9f3ae9845d95496'),
    ('candidate/formal-receive-startup-boundary-timing-v1/runtime/mta_client_service_owner.py',
     107066, 'a73e9646a3f407c2b36a22b67bdcd127945f53e6345b616fe8c646fbbf7837ba'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fresh(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise ValueError('host_result_write')
    if path.read_bytes() != raw:
        raise ValueError('host_result_readback')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-host', action='store_true')
    args = parser.parse_args()
    if not args.run_host:
        print('SOURCE_ONLY; fixed_HOST_method_not_run; no_device')
        return 0
    if any(size <= 0 or len(pin) != 64 for path, size, pin in PINS):
        raise ValueError('host_contract_inputs_unsealed')
    originals = {path: (BASE / path).read_bytes() for path, size, pin in PINS}
    if any((len(originals[path]), sha(originals[path])) != (size, pin)
           for path, size, pin in PINS):
        raise ValueError('host_contract_frozen_input')
    out = BASE / 'results' / ('receive-startup-anchor-clock-v1-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    for path, raw in originals.items():
        fresh(out / 'private-inputs' / path, raw)
    fresh(out / 'private-inputs' / 'host/receive_startup_anchor_clock_v1_host_check.py',
          Path(__file__).read_bytes())
    value = subprocess.run([sys.executable, '-I', '-B', str(BASE / TEST), SELECTOR],
        cwd=str(BASE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    fresh(out / 'private-raw/stdout.raw', value.stdout)
    fresh(out / 'private-raw/stderr.raw', value.stderr)
    unchanged = all((BASE / path).read_bytes() == raw and
                    (out / 'private-inputs' / path).read_bytes() == raw
                    for path, raw in originals.items())
    report = dict(kind='receive_startup_anchor_clock_v1_affected_HOST_contract',
        passed=value.returncode == 0 and unchanged, host_exit=value.returncode,
        source_unchanged=unchanged, methods_requested=1, selector=SELECTOR,
        old_tests_run=0, actual_selected_AST_bodies=True, narrow_fixtures=True,
        fd_content_IO_verified=False, complete_owner_verified=False,
        graph_executed=False, device=False, rf=False, phone=False,
        performance_measured=False,
        sources=[dict(path=p, bytes=n, sha256=h) for p, n, h in PINS])
    public = {'result.json': (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'README.txt': (b'One actual affected HOST method only. Original selected Scope guards, '
                       b'Files.anchors/read/close and Owner clock bodies; narrow context/State/Directory '
                       b'and metadata/FD/content fixtures, not complete Owner or actual kernel IO. '
                       b'Density, call-before-refusal and full IO boundary checks are not measured speed. '
                       b'No old suite, graph, actual FD/content IO, device, RF, phone or measured performance. '
                       b'Raw streams and pinned inputs are private, not included in this scalar ZIP.\n')}
    for path, raw in public.items():
        fresh(out / path, raw)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for path, raw in public.items():
            bundle.writestr(path, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None or any(bundle.read(p) != r for p, r in public.items()):
            raise ValueError('host_result_zip_readback')
    print(json.dumps(dict(passed=report['passed'], host_exit=value.returncode,
                         result=str(out / 'result.json'), zip=str(archive),
                         zip_sha256=sha(archive.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
