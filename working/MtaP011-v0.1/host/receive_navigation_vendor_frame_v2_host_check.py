"""Affected parser HOST contract plus immutable recorded-device adjudication.

No device/window/RF calls. Original navigation FAIL and raw logs are preserved.
Public ZIP contains only finite derived facts and README, not user-bearing logs.
"""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import sys
import traceback
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/receive_navigation_vendor_frame_v2_host_check.py'
LIBRARY = ('host/receive_navigation_vendor_frame_v2.py', 3738,
           '35f7fde1fc30876747c9d856919656662c6856fb15245c38ae5234e6cf33a4aa')
TEST = ('tests/test_receive_navigation_vendor_frame_v2.py', 5705,
        'b2563386a54527cfc819fdfd28876e079e6d65d0206a703a734b65c98b094da6')
ORIGIN = ('host/device_formal_receive_filecenter_navigation_anchor_v1_check.py', 24423,
          '0e9f182b8ff01d8de0020fb3513ddd7b08fd4a33d0d58b10e62543d0ce559e42')
AREA = 'results/formal-receive-filecenter-navigation-classification-v2-navigation-test-20261005-150952-dc89384f/'
RECORDED_LOG = (AREA + 'private-raw/ui-logs/candidate.stderr.raw', 19860,
                '4f4610b655049fbbe4d7c4ee8cac7295832616b067d11069ad62f7d4ab0dbeea')
RECORDED_RESULT = (AREA + 'result.json', 7602,
                   'a6f6ba6aa3c6a508d83be7fa78b226bb80e03849916a81a62aa71052ac06fb47')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if value is not True:
        raise ValueError(code)


def fixed(pin):
    need(type(pin[1]) is int and pin[1] > 0 and len(pin[2]) == 64, 'unsealed_input')
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), sha(raw)) == pin[1:], 'input_pin')
    return raw


def write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)


def main():
    out = BASE / 'results' / ('navigation-vendor-frame-v2-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private'; private.mkdir()
    report = dict(schema='p011-navigation-vendor-frame-v2-host', passed=False,
        test_exit='NOT_RUN', test_timeout=False, host_error=None,
        source_preserved=False, recorded_evidence_preserved=False,
        recorded_navigation_receipt_verified=False, navigation_receipt=None,
        original_run_passed=None, original_error_kind=None,
        recorded_host_exit=None, recorded_remote_exit=None,
        recorded_component_complete=False, recorded_close_facts_verified=False,
        device_invoked=False, original_control_retried=False,
        new_device_window_opened=False, raw_logs_public=False,
        phone_tested=False, full_network_restore_verified=False,
        physical_ui_verified=False, performance_ab_verified=False)
    inputs, own = {}, (BASE / SELF).read_bytes()
    try:
        for pin in (LIBRARY, TEST, ORIGIN, RECORDED_LOG, RECORDED_RESULT):
            inputs[pin[0]] = fixed(pin)
        # Preserve source inputs privately; do not duplicate actual user logs.
        for pin in (LIBRARY, TEST, ORIGIN):
            write_new(private / Path(pin[0]).name, inputs[pin[0]])
        try:
            completed = subprocess.run([sys.executable, '-I', '-B', str(BASE / TEST[0])],
                cwd=str(BASE), capture_output=True, timeout=30, check=False)
            report['test_exit'] = completed.returncode
            write_new(private / 'test.stdout.raw', completed.stdout)
            write_new(private / 'test.stderr.raw', completed.stderr)
        except subprocess.TimeoutExpired as error:
            report['test_timeout'] = True
            write_new(private / 'test.stdout.raw', error.stdout or b'')
            write_new(private / 'test.stderr.raw', error.stderr or b'')
            raise
        need(report['test_exit'] == 0 and report['test_timeout'] is False, 'affected_host_contract')
        spec = importlib.util.spec_from_file_location('fixed_navigation_vendor_frame_v2', BASE / LIBRARY[0])
        library = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(library)
        need(library.ORIGIN == ORIGIN, 'actual_parser_origin')
        receipt = library.navigation_receipt(inputs[RECORDED_LOG[0]])
        report['navigation_receipt'] = receipt
        report['recorded_navigation_receipt_verified'] = True
        old = json.loads(inputs[RECORDED_RESULT[0]].decode('ascii'))
        need(old['passed'] is False and old['error_kind'] == 'NavigationReceiptError' and
             old['host_exit'] == 0 and old['remote_exit'] == 0 and
             old['phone_tested'] is False, 'original_device_result_identity')
        component = old['component']
        need(type(component) is dict and component['complete'] is True and
             component['reason'] == 'receive_filecenter_navigation_finished' and
             component['ui_ready'] is True and component['navigation_receive_activity_free'] is True and
             component['navigation_cancelled_empty_observed'] is True and
             component['navigation_display_finished'] is True and
             component['receive_trial_claim_count'] == 0 and component['receive_trial_claimed'] is False and
             component['receive_trial_session_attached'] is False and
             component['resource_pending'] is False, 'recorded_runtime_facts')
        closed = ('owner_close_verified', 'startup_resources_closed', 'filecenter_audio_settled',
                  'filecenter_close_called', 'filecenter_closed', 'guardian_exited',
                  'credentials_removed', 'candidate_exited', 'worker_fds_closed', 'stock_restored')
        need(all(component[key] is True for key in closed) and
             old['stock_after_verified'] is True and old['stock_before_verified'] is True and
             old['stock_files_unchanged'] is True and old['carrier_files_after_verified'] is True,
             'recorded_close_facts')
        report.update(original_run_passed=False, original_error_kind=old['error_kind'],
            recorded_host_exit=old['host_exit'], recorded_remote_exit=old['remote_exit'],
            recorded_component_complete=True, recorded_close_facts_verified=True)
    except Exception as error:
        report['host_error'] = type(error).__name__
        write_new(private / 'host-error.txt', traceback.format_exc().encode('utf-8'))
    finally:
        try:
            report['source_preserved'] = bool(inputs) and (BASE / SELF).read_bytes() == own and all(
                (BASE / pin[0]).read_bytes() == inputs[pin[0]] and
                (private / Path(pin[0]).name).read_bytes() == inputs[pin[0]]
                for pin in (LIBRARY, TEST, ORIGIN))
            report['recorded_evidence_preserved'] = all(
                (BASE / pin[0]).read_bytes() == inputs[pin[0]]
                for pin in (RECORDED_LOG, RECORDED_RESULT))
        except Exception:
            report['source_preserved'] = report['recorded_evidence_preserved'] = False
    report['passed'] = (report['host_error'] is None and report['test_exit'] == 0 and
        not report['test_timeout'] and report['source_preserved'] and report['recorded_evidence_preserved'] and
        report['recorded_navigation_receipt_verified'] and report['recorded_component_complete'] and
        report['recorded_close_facts_verified'])
    report['input_pins'] = [dict(path=pin[0], bytes=pin[1], sha256=pin[2])
                            for pin in (LIBRARY, TEST, ORIGIN, RECORDED_LOG, RECORDED_RESULT)]
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Affected HOST parser contract plus derived adjudication of an immutable actual P011 navigation log. '
        b'The original run remains FAIL (NavigationReceiptError); actual component and remote exit were successful. '
        b'Only an observed strict vendor presentation prefix is canonicalized before the frozen original15-field parser. '
        b'Marker count, full line, JSON bounds/unique keys, one real click and all prohibited business/file/media facts stay. '
        b'No new device/control/window/RF/phone/file transfer or performance A/B. '
        b'Actual log/result inputs were read and checked unchanged; no raw user logs are included in this public ZIP. '
        b'The derived receipt proves the recorded click/cancel/fresh-status/Received-stability event only, '
        b'not physical touch, phone compatibility, received content or full network restoration.\n')
    write_new(out / 'result.json', public); write_new(out / 'README.txt', readme)
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', public); archive.writestr('README.txt', readme)
    with zipfile.ZipFile(bundle) as archive:
        need(archive.namelist() == ['result.json', 'README.txt'] and archive.testzip() is None and
             archive.read('result.json') == public and archive.read('README.txt') == readme, 'zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        zip_sha256=sha(bundle.read_bytes()), device_invoked=False), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
