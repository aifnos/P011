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
TEST = 'tests/test_receive_startup_boundary_timing_v1.py'
SELECTOR = ('ReceiveStartupBoundaryTimingV1Contract.'
            'test_actual_startup_boundaries_preserve_original_call_and_error')
PINS = (
    (TEST, 14042, '890ea093aa5fee10a52184ab79993665f758c51c29fc51427625a04494231d9f'),
    ('candidate/receive-startup-boundary-timing-v1/runtime/mta_client_receive_factory.py',
     89974, 'b4803dea9eeb9421d773a991e1fc7315dfd7990c42ae629879bfa06b912bdc81'),
    ('candidate/formal-receive-startup-alias-clock-v1/runtime/mta_client_receive_factory.py',
     89379, '4a1043e3eb3fbcc3e80927b64640d80c350c38d4bd2c6ecf73eeff68bf15c35d'),
    ('candidate/receive-startup-boundary-timing-v1/exactsource-delta.json',
     3209, '35981ad265cf131ade91ea6fdf422e347b11a6190ad6b4f450694c8a9853b565'))


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
    originals = {path: (BASE / path).read_bytes() for path, size, pin in PINS}
    if any((len(originals[path]), sha(originals[path])) != (size, pin)
           for path, size, pin in PINS):
        raise ValueError('host_contract_frozen_input')
    out = BASE / 'results' / ('receive-startup-boundary-timing-v1-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    for path, raw in originals.items():
        fresh(out / 'private-inputs' / path, raw)
    fresh(out / 'private-inputs' / 'host/receive_startup_boundary_timing_v1_host_check.py',
          Path(__file__).read_bytes())
    value = subprocess.run([sys.executable, '-I', '-B', str(BASE / TEST), SELECTOR],
        cwd=str(BASE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    fresh(out / 'private-raw/stdout.raw', value.stdout)
    fresh(out / 'private-raw/stderr.raw', value.stderr)
    unchanged = all((BASE / path).read_bytes() == raw and
                    (out / 'private-inputs' / path).read_bytes() == raw
                    for path, raw in originals.items())
    report = dict(kind='receive_startup_boundary_timing_v1_affected_HOST_contract',
        passed=value.returncode == 0 and unchanged, host_exit=value.returncode,
        source_unchanged=unchanged, methods_requested=1, selector=SELECTOR,
        old_tests_run=0, actual_selected_AST_bodies=True, narrow_fixtures=True,
        fd_content_IO_verified=False, complete_owner_verified=False,
        graph_executed=False, device=False, rf=False, phone=False,
        performance_measured=False,
        sources=[dict(path=p, bytes=n, sha256=h) for p, n, h in PINS])
    public = {'result.json': (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'README.txt': (b'One actual affected HOST method only. Original selected Scope.__init__, '
                       b'Scope.check_active and Factory.startup_readonly bodies. Owner/context, '
                       b'Files/profile/importer/close are narrow fixtures. '
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
