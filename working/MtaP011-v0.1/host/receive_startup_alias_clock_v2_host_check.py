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
TEST = 'tests/test_receive_startup_alias_clock_v2.py'
SELECTOR = ('ReceiveStartupAliasClockV2Contract.'
            'test_actual_alias_density_full_io_and_original_code_refusal')
PINS = (
    (TEST, 15186, 'e286d4f48ed2460814326e6c2ef90cf6b9940d2c8417d8c62d4c052f6663ee80'),
    ('candidate/receive-startup-alias-clock-v2/runtime/mta_client_receive_factory.py',
     89375, 'c018edb57aa5824b87d4fc731aa12710cb113c18ca064afecff23f8dd597bb1a'),
    ('candidate/formal-receive-filecenter-v1/runtime/mta_client_executor.py',
     117754, '2a6b596004f9f34ef46359f3cb82e4742b82025ff537d70296bb5c5dd8b083b5'),
    ('candidate/formal-receive-filecenter-v1/runtime/mta_client_service_owner.py',
     107054, 'f6a1f670899129a26da2e6c66e6d4166b1787ee52a940c945b992dfd7319828d'))


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
    out = BASE / 'results' / ('receive-startup-alias-clock-v2-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    for path, raw in originals.items():
        fresh(out / 'private-inputs' / path, raw)
    fresh(out / 'private-inputs' / 'host/receive_startup_alias_clock_v2_host_check.py',
          Path(__file__).read_bytes())
    value = subprocess.run([sys.executable, '-I', '-B', str(BASE / TEST), SELECTOR],
        cwd=str(BASE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    fresh(out / 'private-raw/stdout.raw', value.stdout)
    fresh(out / 'private-raw/stderr.raw', value.stderr)
    unchanged = all((BASE / path).read_bytes() == raw and
                    (out / 'private-inputs' / path).read_bytes() == raw
                    for path, raw in originals.items())
    report = dict(kind='receive_startup_alias_clock_v2_affected_HOST_contract',
        passed=value.returncode == 0 and unchanged, host_exit=value.returncode,
        source_unchanged=unchanged, methods_requested=1, selector=SELECTOR,
        old_tests_run=0, actual_selected_AST_bodies=True, narrow_fixtures=True,
        fd_content_IO_verified=False, complete_owner_verified=False,
        graph_executed=False, device=False, rf=False, phone=False,
        performance_measured=False,
        sources=[dict(path=p, bytes=n, sha256=h) for p, n, h in PINS])
    public = {'result.json': (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'README.txt': (b'One actual affected HOST method only. Original selected Scope/ReadOwner/Files/'
                       b'Owner._now bodies with narrow metadata, Directory, State and _context fixtures. '
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
