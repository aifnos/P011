"""One affected HOST fixture method; no runtime main, ADB or radio action."""
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
SELF = 'host/receive_navigation_refusal_projection_v1_host_check.py'
TEST = 'tests/test_receive_navigation_refusal_projection_v1.py'
SELECTOR = 'NavigationRefusalProjectionV1Contract.test_actual_guard_short_circuit_and_cached_data'
PINS = (
    (TEST, 23140, '99bcdb66b0b6d0875ddd57114ac7c8273d8cfe5b47a7fab81bb88b8661e7d3be'),
    ('candidate/formal-receive-filecenter-navigation-publication-v1/runtime/mta_formal_receive_session.py',
     85546, '521f5110bafdbde3a3539fff5f2b2a53a911a8e1008597ca646e3b0acff8ca8b'),
    ('candidate/formal-receive-filecenter-navigation-publication-v2/runtime/ui_session.py',
     95260, '68aa90855e6109714c9e8e091d266eb7900dba5a4129d75a3fc943543e3ed19a'),
    ('candidate/formal-receive-filecenter-navigation-publication-v3/runtime/mta_formal_receive_session.py',
     88817, 'a54c40de4ad1b0a59ed81191ad7768d6d0783d2acb4b7aa58a84d010bd3b812f'),
    ('candidate/formal-receive-filecenter-navigation-publication-v3/runtime/ui_session.py',
     95419, '2661710612069f9381dea2049721147cab01f2b1ac67e3d22628fa609b90d80c'),
    ('host/receive_navigation_refusal_projection_v1.py',
     7474, 'c48192bd978e0bb056f5ea0c74617628b6d9e27936ca9e5697310e39b7bb1bb4'),
    ('candidate/formal-receive-filecenter-navigation-publication-v3/exactsource-delta.json',
     19340, '2b1a84e35fa27a546248d70d4780d73e37622eb4b37ec6f453d942278261e812'))


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
        print('SOURCE_ONLY; affected_HOST_method_not_run; no_device')
        return 0
    if len(PINS) != 7 or not any(path == TEST for path, size, pin in PINS):
        raise ValueError('host_input_inventory')
    originals = {path: (BASE / path).read_bytes() for path, size, pin in PINS}
    if any((len(originals[path]), sha(originals[path])) != (size, pin)
           for path, size, pin in PINS):
        raise ValueError('host_input_identity')
    originals[SELF] = Path(__file__).read_bytes()
    out = BASE / 'results' / ('navigation-refusal-projection-v1-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    for path, raw in originals.items():
        fresh(out / 'private-inputs' / path, raw)
    code, timed_out = None, False
    started = time.monotonic()
    try:
        process = subprocess.run([sys.executable, '-I', '-B', str(BASE / TEST), SELECTOR],
            cwd=str(BASE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        code, stdout, stderr = process.returncode, process.stdout, process.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        stdout, stderr = error.stdout or b'', error.stderr or b''
    elapsed = time.monotonic() - started
    fresh(out / 'private-raw/stdout.raw', stdout)
    fresh(out / 'private-raw/stderr.raw', stderr)
    unchanged = all((BASE / path).read_bytes() == raw and
                    (out / 'private-inputs' / path).read_bytes() == raw
                    for path, raw in originals.items())
    passed = code == 0 and unchanged and not timed_out
    report = dict(kind='navigation_refusal_projection_v1_affected_HOST', passed=passed,
        test_exit=code, host_exit=0 if passed else 1, timed_out=timed_out,
        host_elapsed_seconds=elapsed, source_unchanged=unchanged, methods_requested=1,
        selector=SELECTOR, old_tests_run=0, actual_selected_observer_and_guard_AST=True,
        actual_target_projection_fragment=True, selected_code_binding_fixture=True,
        owner_state_trial_http_fixtures=True, complete_owner_verified=False,
        graph_executed=False, candidate_packaged=False, device=False, rf=False, phone=False,
        performance_measured=False, actual_qttest_receipt_verified=False,
        streams=[dict(name=name, bytes=len(raw), sha256=sha(raw))
                 for name, raw in (('stdout.raw', stdout), ('stderr.raw', stderr))],
        sources=[dict(path=path, bytes=len(raw), sha256=sha(raw))
                 for path, raw in originals.items()])
    public = {'result.json': (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'README.txt': (
            b'One actual selected observer and navigation guard HOST method, with explicit '
            b'Owner/State/Trial/HTTP fixtures. No full runtime main, graph, native device, '
            b'RF, phone, GUI click or performance acceptance. Cached observations retain '
            b'their original selected-code bindings in explicit HOST fixtures, not a full Worker. '
            b'their original order and are not one atomic state snapshot. '
            b'Unchanged earlier suites are not repeated. Raw streams and pinned sources '
            b'remain private; public ZIP contains scalar result and this scope only.\n')}
    for path, raw in public.items():
        fresh(out / path, raw)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for path, raw in public.items():
            bundle.writestr(path, raw)
    with zipfile.ZipFile(archive) as bundle:
        if (set(bundle.namelist()) != set(public) or bundle.testzip() is not None or
                any(bundle.read(path) != raw for path, raw in public.items())):
            raise ValueError('host_zip_readback')
    print(json.dumps(dict(passed=passed, test_exit=code, host_exit=report['host_exit'],
        timed_out=timed_out, result=str(out / 'result.json'), zip=str(archive),
        zip_sha256=sha(archive.read_bytes())), sort_keys=True))
    return report['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
