"""One affected status HOST fixture; no full State, runtime graph or device.

Keep the selected pinned deploy-v5 source/manifest unchanged. Execute only the
new test's actual status method selection on immutable PC snapshots. Public
ZIP contains finite fixture facts and README, never raw/source/user data.
"""
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import traceback
import zipfile


BASE = Path(__file__).resolve().parents[1]
SELF = 'host/formal_send_cancel_status_v1_host_check.py'
CMD = 'HOST_MTA_FORMAL_SEND_CANCEL_STATUS_V1_CHECK.cmd'
TEST = ('tests/test_formal_send_cancel_status_v1.py', 12445,
        '0dd72a6ffc6a39a49742e531f27aeb7516847201529d9140c4adfc7c19f4ae62')
ORIGIN = ('candidate/formal-send-filecenter-deploy-v5/runtime/mta_service.py', 145540,
          '64a74b3e9082ac06070377d541544e29766f93887c39dcc92d72a87d7ceb7e51')
CANDIDATE = ('candidate/formal-send-cancel-status-v1/runtime/mta_service.py', 145733,
             '4b1971056673e492e42d59410594192ea7165687ec0ac807cb61deccd5e75d82')
MANIFEST = ('candidate/formal-send-filecenter-deploy-v5/assets/ordinary-source-manifest.json', 20796,
            'd000945a5e749a7f4d651305ef0e3a0b9f7fce96ffc2360dfed04b0d37ba230c')
DELTA = ('candidate/formal-send-cancel-status-v1/exactsource-delta.json', 1458,
         '1dcaa43c0d0bc465bda3e8a1b0f8ea18f342346713fb80e1e5a3dff0f6e4d2aa')
PINS = (TEST, ORIGIN, CANDIDATE, MANIFEST, DELTA)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise OSError('short_write')
    if path.read_bytes() != raw:
        raise ValueError('snapshot_readback')


def main():
    if sys.argv[1:]:
        raise ValueError('fixed_HOST_only')
    out = BASE / 'results' / ('formal-send-cancel-status-v1-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, stdout, stderr = {}, b'', b''
    report = dict(schema='p011-formal-send-cancel-status-v1-host', passed=False,
        test_exit='NOT_RUN', host_timeout=False, host_error=None,
        remote_exit='NOT_RUN_HOST_ONLY', source_preserved=False,
        selected_methods_per_source=1, affected_test_methods=1,
        fixture_case_count=0, fixture_case_names=[], actual_selected_state_status_method=True,
        session_lifecycle_is_fixture=True, dependency_predicates_are_fixtures=True,
        synthetic_monotonic_clock=True, host_mutex_real=True,
        original_and_candidate_call_order_compared=True,
        whole_state_constructor=False, actual_session=False, actual_operation=False,
        actual_send_worker=False, actual_receive_bridge=False, actual_network_probes=False,
        ordinary_graph_repackaged=False, old_manifest_modified=False,
        native=False, device=False, phone=False, ui=False, rf=False,
        send_verified=False, success_verified=False, restoration_verified=False,
        candidate_deployed=False, production_admitted=False,
        raw_or_source_files_public=False)
    try:
        for pin in PINS:
            raw = (BASE / pin[0]).read_bytes()
            if (len(raw), digest(raw)) != pin[1:]:
                raise ValueError('fixed_input_pin')
            inputs[pin[0]] = raw
        for path in (SELF, CMD):
            inputs[path] = (BASE / path).read_bytes()
        for path, raw in inputs.items():
            save(out / 'private-inputs' / path, raw)
        save(out / 'private-inputs.json', (json.dumps({path: dict(bytes=len(raw), sha256=digest(raw))
            for path, raw in inputs.items()}, sort_keys=True, indent=2) + '\n').encode('ascii'))
        try:
            child = subprocess.run([sys.executable, '-I', '-B',
                str(out / 'private-inputs' / TEST[0])], cwd=str(out / 'private-inputs'),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=30, check=False)
            stdout, stderr = child.stdout, child.stderr
            report['test_exit'] = child.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            report['host_timeout'] = True
        marks = re.findall(rb'^FORMAL_SEND_CANCEL_STATUS_CASES=([0-9]+)\r?$', stdout, re.M)
        cases = re.findall(rb'^FORMAL_SEND_CANCEL_STATUS_CASE=([a-z0-9_]+)\r?$', stdout, re.M)
        report['fixture_case_count'] = int(marks[0]) if len(marks) == 1 else 0
        report['fixture_case_names'] = [name.decode('ascii') for name in cases]
        if (report['test_exit'] != 0 or report['host_timeout'] or
                report['fixture_case_count'] != 33 or len(cases) != 33 or len(set(cases)) != 33 or
                re.search(rb'^Ran 1 test in [0-9.]+s\r?$', stderr, re.M) is None or
                re.search(rb'^OK\r?$', stderr, re.M) is None):
            raise ValueError('affected_status_fixture_failed')
    except Exception as error:
        report['host_error'] = type(error).__name__
        save(private / 'host-error.txt', traceback.format_exc().encode('utf-8'))
    finally:
        for tag, raw in (('stdout', stdout), ('stderr', stderr)):
            save(private / (tag + '.raw'), raw)
            report[tag + '_bytes'], report[tag + '_sha256'] = len(raw), digest(raw)
        save(private / 'test-exit.raw', (str(report['test_exit']) + '\n').encode('ascii'))
        save(private / 'remote-exit.raw', b'NOT_RUN_HOST_ONLY\n')
        try:
            report['source_preserved'] = bool(inputs) and all(
                (BASE / path).read_bytes() == raw and (out / 'private-inputs' / path).read_bytes() == raw
                for path, raw in inputs.items())
        except Exception:
            report['source_preserved'] = False
    report['source_count'] = len(inputs)
    report['input_pins'] = [dict(path=pin[0], bytes=pin[1], sha256=pin[2]) for pin in PINS]
    report['passed'] = (report['host_error'] is None and report['test_exit'] == 0 and
        not report['host_timeout'] and report['fixture_case_count'] == 33 and report['source_preserved'])
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'One new HOST method /33 synthetic dependency cases executes only the actual selected '
        b'State.status method from pinned selected deploy-v5 and the single-block candidate. '
        b'Byte forward/inverse proof retains the whole original source and selected old manifest unchanged. '
        b'Only sending+closed+cancelled idle reason changes when original aggregate pending is false. '
        b'Pending wifi/radio/probes/GO keeps original reason bytes/value; original restoring branch, '
        b'completed/sent_unconfirmed/failed, receive/no-session/GO progress, transfer bytes, capability '
        b'fields and dependency call order/count are compared with actual original method outputs. '
        b'Cancelled is not a send-success or network-restoration certificate and does not zero sent bytes. '
        b'Session lifecycle, probes, GO/bridge/worker type/deadline DATA and admission decisions are explicit '
        b'HOST fixtures; the lock is real HOST RLock. No whole State constructor, actual Session/worker '
        b'Owner/Parent, native/IO/RF, UI, P011, phone, send or restoration runs. No old suite is replayed. '
        b'Independent candidate is not admitted to any deployed source graph. '
        b'Raw logs and exact source snapshots stay private; public ZIP is result.json plus README only.\n')
    save(out / 'result.json', public); save(out / 'README.txt', readme)
    bundle_path = out / 'public-result.zip'
    with zipfile.ZipFile(bundle_path, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public); bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(bundle_path) as bundle:
        if (bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None or
                bundle.read('result.json') != public or bundle.read('README.txt') != readme):
            raise ValueError('public_zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        zip_sha256=digest(bundle_path.read_bytes()), device=False), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
