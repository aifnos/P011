"""One fixed affected HOST method; private raw and public scalar results only."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/receive_publication_anchor_clock_v1_host_check.py'
TEST = 'tests/test_receive_publication_anchor_clock_v1.py'
SELECTOR = ('ReceivePublicationAnchorClockV1Contract.'
            'test_actual_publication_anchor_density_io_and_refusals')
PINS = (
    (TEST, 22471, 'fb776d793f4a0d4a146cdfd7804c33dfda06bc4e7553ad1c31c816631183f5c1'),
    ('candidate/receive-publication-anchor-clock-v1/runtime/mta_client_receive_factory.py',
     94385, '2933d86ab3ce25b20b4efc0eea7733770b2209cc5c5ac062c52793bfceb6da79'),
    ('candidate/formal-receive-startup-anchor-clock-v1/runtime/mta_client_receive_factory.py',
     91901, '0799fe739a9a3de15fd15453d7ddf6df4c49e411ea30c2c0d9911ab73b1b29c8'),
    ('candidate/receive-publication-anchor-clock-v1/exactsource-delta.json',
     9829, 'f65512055f7c232d01d920e33508579b889762a0b614a0100ba372fbe230feec'),
    ('candidate/formal-receive-startup-anchor-clock-v1/runtime/mta_client_executor.py',
     117757, 'fc723a7479d4b2d142b9024a2003de0eb5fcd0b907a4a0c6f91e7af2c2a7d3e2'),
    ('HOST_MTA_RECEIVE_PUBLICATION_ANCHOR_CLOCK_V1_CHECK.cmd',
     281, '3400a4b87a5f82a6330886ed44186fc2f4f93fb6ee98149457736c82087e3ca6'))


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
    originals[SELF] = Path(__file__).read_bytes()
    out = BASE / 'results' / ('receive-publication-anchor-clock-v1-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    for path, raw in originals.items():
        fresh(out / 'private-inputs' / path, raw)
    test_exit, timed_out = None, False
    started = time.monotonic()
    try:
        value = subprocess.run([sys.executable, '-I', '-B', str(BASE / TEST), SELECTOR],
            cwd=str(BASE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        test_exit, stdout, stderr = value.returncode, value.stdout, value.stderr
    except subprocess.TimeoutExpired as error:
        # subprocess.run has killed/waited its own PC child; do not invent an
        # observed child exit code. Keep the original partial output bytes.
        timed_out = True
        stdout, stderr = error.stdout or b'', error.stderr or b''
    elapsed = time.monotonic() - started
    fresh(out / 'private-raw/stdout.raw', stdout)
    fresh(out / 'private-raw/stderr.raw', stderr)
    unchanged = all((BASE / path).read_bytes() == raw and
                    (out / 'private-inputs' / path).read_bytes() == raw
                    for path, raw in originals.items())
    passed = test_exit == 0 and unchanged and not timed_out
    host_exit = 0 if passed else 1
    report = dict(kind='receive_publication_anchor_clock_v1_affected_HOST_contract',
        passed=passed, test_exit=test_exit, host_exit=host_exit, timed_out=timed_out,
        host_elapsed_seconds=elapsed, host_platform=sys.platform,
        python_version=list(sys.version_info[:3]), source_unchanged=unchanged,
        methods_requested=1, selector=SELECTOR, old_tests_run=0,
        actual_selected_Files_AST_bodies=True, actual_executor_metadata_helpers=True,
        publication_clock_factory_received_fixtures=True, fd_content_IO_fixtures=True,
        startup_branch_compared_as_DATA_only=True, startup_tests_run=0,
        complete_publication_verified=False, complete_owner_verified=False,
        native_fd_content_IO_verified=False, graph_executed=False,
        candidate_packaged=False, device=False, rf=False, phone=False,
        performance_measured=False,
        streams=[dict(name=name, bytes=len(raw), sha256=sha(raw))
                 for name, raw in (('stdout.raw', stdout), ('stderr.raw', stderr))],
        sources=[dict(path=p, bytes=len(raw), sha256=sha(raw))
                 for p, raw in originals.items()])
    public = {'result.json': (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'README.txt': (
            b'One fixed affected HOST method, not an actual Publication/Owner/phone trial. '
            b'Actual pinned Files anchors/read/close and executor metadata/readlink helpers; '
            b'Publication clocks, Factory, Received directory and FD/content IO are narrow fixtures. '
            b'Unchanged Startup branch is compared as DATA only; no old Startup/suite/main is run. '
            b'Full/metadata density, original stat/IO ordering and zero-call mutation refusals '
            b'are not measured device speed or native descriptor evidence. '
            b'Host elapsed is PC selector process time only. Candidate is not packaged or deployable. '
            b'Raw stdout/stderr and all pinned inputs remain private and are not in this public ZIP.\n')}
    for path, raw in public.items():
        fresh(out / path, raw)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for path, raw in public.items():
            bundle.writestr(path, raw)
    with zipfile.ZipFile(archive) as bundle:
        if (set(bundle.namelist()) != set(public) or bundle.testzip() is not None or
                any(bundle.read(p) != r for p, r in public.items())):
            raise ValueError('host_result_zip_readback')
    print(json.dumps(dict(passed=passed, test_exit=test_exit, host_exit=host_exit,
                         timed_out=timed_out, result=str(out / 'result.json'),
                         zip=str(archive), zip_sha256=sha(archive.read_bytes())), sort_keys=True))
    return host_exit


if __name__ == '__main__':
    raise SystemExit(main())
