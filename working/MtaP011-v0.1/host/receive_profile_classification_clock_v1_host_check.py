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
SELF = 'host/receive_profile_classification_clock_v1_host_check.py'
TEST = 'tests/test_receive_profile_classification_clock_v1.py'
SELECTOR = ('ReceiveProfileClassificationClockV1Contract.'
            'test_actual_profile_classification_io_and_refusals')
PINS = (
    (TEST, 27430, 'af393f6151ce073fe56e0f68d7240cd705720518933db59b13a6c5687af98a3e'),
    ('candidate/receive-profile-classification-clock-v1/runtime/mta_client_receive_factory.py',
     97801, '8cf46d17fda24cc2199e8900a0dfdd9d980b2247808c87801c00426db6158c37'),
    ('candidate/formal-receive-publication-anchor-clock-v1/runtime/mta_client_receive_factory.py',
     94393, '887942d83faf27f781981f426cce5890fa4894219365545901df9310887cd8d3'),
    ('candidate/receive-profile-classification-clock-v1/exactsource-delta.json',
     4360, '676ff4a410e882dc75c7750d7b5e02d110919ca41b5e14895141b1c3d1a6d7ae'),
    ('candidate/formal-receive-publication-anchor-clock-v1/runtime/mta_client_executor.py',
     117761, '34eddfee126c771776808e64a746f2186f61065cfce9a0c2e59e23e85d67ae23'),
    ('candidate/formal-receive-publication-anchor-clock-v1/runtime/mta_client_service_owner.py',
     107068, '745c9569d43711d2dd3f1cf3b29b415020d7163fc7a956bf3b64347a0bda4bcb'),
    ('HOST_MTA_RECEIVE_PROFILE_CLASSIFICATION_CLOCK_V1_CHECK.cmd',
     267, 'a4e9923e1dbc119c0915005a10fde0061194e9581e99e7d6404440c6e62c23ed'))


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
    out = BASE / 'results' / ('receive-profile-classification-clock-v1-host-' +
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
    report = dict(kind='receive_profile_classification_clock_v1_affected_HOST_contract',
        passed=passed, test_exit=test_exit, host_exit=host_exit, timed_out=timed_out,
        host_elapsed_seconds=elapsed, host_platform=sys.platform,
        python_version=list(sys.version_info[:3]), source_unchanged=unchanged,
        methods_requested=1, selector=SELECTOR, old_tests_run=0,
        actual_selected_live_profile_prefix=True, actual_selected_Files_AST_bodies=True,
        actual_startup_publication_alias_guards=True, actual_owner_now_body=True,
        actual_executor_metadata_helpers=True, parent_owner_context_fixture=True,
        handoff_trial_bridge_directory_fixtures=True, fd_content_IO_fixtures=True,
        complete_live_profile_executed=False, old_startup_suite_run=False,
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
            b'One fixed affected HOST classification method, not a complete live profile/Owner/phone trial. '
            b'Actual pinned live-profile prefix through classification For, Files IO/close, '
            b'Startup/Publication clock guards, Owner._now and executor metadata helpers. '
            b'Owner._context, Handoff/Trial/Bridge/Directory and descriptor/content IO are narrow fixtures. '
            b'The selected prefix stops before daemon continuity/full-profile completion. '
            b'Delayed full Directory/Handoff failure must reject before the next actual IO in this fixture; '
            b'this is not identical first-error/side-effect timing or native IO/device performance proof. '
            b'No old methods/suite/main, graph, build, device or RF actions are requested. '
            b'Host elapsed is PC selector process time only. Candidate is not packaged. '
            b'Raw stdout/stderr and pinned inputs remain private, not in this metadata-only public ZIP.\n')}
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
