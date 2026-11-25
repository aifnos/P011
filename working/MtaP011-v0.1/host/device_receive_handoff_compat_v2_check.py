"""Independent v2 startup-root closure plus frozen Handoff/trace; default PC SOURCE.

Frozen phone-v1/trace-v1 bytes remain unchanged. New mechanical graph paths and
known-field projection are source-pinned. Only --check-device explicitly
runs the existing phone discovery/cancel with finite diagnostic tracing. No UI,
accept/send, record cleanup or fabricated restoration. Pending remains original.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import threading
import traceback
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_handoff_compat_v2_check.py'
CMDS = ('HOST_MTA_RECEIVE_HANDOFF_COMPAT_V2_CHECK.cmd', 'TEST_MTA_RECEIVE_HANDOFF_COMPAT_V2.cmd',
        'HOST_MTA_RECEIVE_HANDOFF_COMPAT_V2_CONTRACT.cmd')
DIAGNOSTIC = ('host/device_receive_advertise_smoke_v2_diagnostic.py', 19645,
              'c33a0e73569ddac453230e0ba509955a4b08a84742633b021c433b8dc77d6201')
RUNTIME_V2 = ('candidate/receive-phone-discovery-v1/runtime/phone_discovery_session.py', 16332,
              '66554a39a63f95bad6b683f2121dd3a58417ab2b63168dd2a1db4a72eda0b34e')

PHONE_HOST = ('host/device_receive_phone_discovery_v1_check.py', 20192,
              '09fb7cd14876d04916db1aca0eaf40c437dadcf79b7bee1354f3cb1cb605bcbc')
TRACE = ('candidate/receive-handoff-trace-v1/runtime/handoff_trace.py', 14820,
         '990cbf387893706e263abc43aa4fdc728782c4a0a88de531d5a1a53274862657')
TEST_SOURCE = 'tests/test_receive_handoff_compat_v2.py'
COMPAT = ('host/formal_receive_compat_v2_definitions.py', 9834,
          '9836f38f5fe48b7ef2e0f5a33f8b58a2ad80648c572410d54e7892f7d05e0b04')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise OSError('short_write')


def load_phone():
    raw = (BASE / PHONE_HOST[0]).read_bytes()
    if len(raw) != PHONE_HOST[1] or digest(raw) != PHONE_HOST[2]:
        raise ValueError('phone_host_pin')
    phone = types.ModuleType('fixed_phone_v1_definitions')
    phone.__file__ = str(BASE / PHONE_HOST[0])
    exec(compile(raw, phone.__file__, 'exec'), phone.__dict__)
    return phone, raw


def make_source(original, v1, diagnostic, helpers, inputs, payload):
    phone, unused = load_phone()
    old = phone.make_source(original, v1, diagnostic, helpers, inputs, payload)
    marker = b'result=smoke.run_fixed(session,artifacts)\n'
    if old.count(marker) != 1:
        raise ValueError('phone_call_changed')
    prefix = ('TRACE_PIN=' + repr(TRACE[1:]) + '\nTRACE_ENCODED=(\n' +
              original._short_chunks(helpers, inputs[TRACE[0]]) + '\n)\n' +
              "trace=types.ModuleType('fixed_receive_handoff_trace')\n" +
              "trace.__file__='<fixed-receive-handoff-trace-stdin>'\n" +
              'exec(fixed_decode(TRACE_ENCODED,TRACE_PIN[0],TRACE_PIN[1]),trace.__dict__)\n' +
              'try:\n result=trace.run_fixed(session,artifacts,smoke)\n' +
              'except BaseException:\n' +
              " print('HANDOFF_TRACE_RESULT='+repr(trace.public_result()),flush=True)\n raise\n" +
              "print('HANDOFF_TRACE_RESULT='+repr(trace.public_result()),flush=True)\n").encode('ascii')
    program = old.replace(marker, prefix)
    if len(program) > 2097152 or any(len(line) > 256 for line in program.splitlines()):
        raise ValueError('target_source_budget')
    return program


def parse_trace(diagnostic, raw):
    value = diagnostic.one_literal(raw, 'HANDOFF_TRACE_RESULT')
    keys = {'schema', 'thread_trace_installed', 'thread_trace_hook_restored', 'trace_unknown',
            'overflow_unknown', 'failure_codes', 'events', 'terminal'}
    if type(value) is not dict or set(value) != keys or value['schema'] != 'receive-handoff-trace-v1':
        raise ValueError('trace_fields')
    for name in ('thread_trace_installed', 'thread_trace_hook_restored', 'trace_unknown', 'overflow_unknown'):
        if type(value[name]) is not bool:
            raise ValueError('trace_bool')
    failures = {'existing_trace', 'install_failed', 'hook_changed', 'current_hook_changed',
                'projection_failed', 'source_changed', 'event_overflow', 'event_contended', 'terminal_unknown'}
    if (type(value['failure_codes']) is not tuple or len(value['failure_codes']) > len(failures) or
            any(type(item) is not str or item not in failures for item in value['failure_codes'])):
        raise ValueError('trace_failure')
    allowed_keys = {'kind', 'code', 'module', 'function', 'line', 'handoff_flags', 'actor_unknown',
        'cancel_requested', 'input_ready', 'radio_restore_pending', 'wifi_restore_pending',
        'receive_extra_verified', 'radio_probes', 'failed', 'cancelled', 'received',
        'decrypt_attempted', 'claimed', 'source', 'actors_closed', 'failure', 'call_returned',
        'error_present', 'before_actor', 'current_actor', 'before_normalized', 'current_normalized',
        'normalization_errors', 'field_equal', 'counts', 'comparison_matches', 'bluez_owner',
        'current_settings', 'powered', 'bredr_enabled', 'le_enabled', 'global_advertising',
        'bluez_advertising_active', 'connectable_advert', 'discovering', 'discoverable', 'pairable',
        'max_adv', 'max_scan', 'max_instances', 'active_instances', 'active_instance_ids',
        'connected_devices', 'connected_before', 'connected_after', 'adv_before', 'adv_after'}
    allowed_strings = {'HandoffError', 'ProtocolError', 'RadioObservationError', 'ValueError',
        'TypeError', 'UnicodeError', 'UnicodeDecodeError', 'UnicodeEncodeError', 'RuntimeError',
        'OverflowError', 'OtherError', 'present', 'mta_client_connect_handoff', 'mta_protocol',
        '_check', 'capture', 'decode_json', '_base64', '_integer', 'validate_task_id',
        'P2pInfo.__init__', 'P2pInfo.from_dict', 'invalid_owner', 'invalid_budget', 'wrong_thread',
        'cancelled', 'expired', 'invalid_event', 'already_received', 'not_received',
        'decrypt_failed', 'already_claimed', 'invalid_binding', 'frame_failed', 'radio_schema',
        'radio_unknown', 'radio_fields', 'radio_inconsistent', 'radio_instances', 'radio_peers'}
    def finite(item, depth=0):
        if depth > 6:
            return False
        if item is None or type(item) is bool:
            return True
        if type(item) is int:
            return 0 <= item <= 10000
        if type(item) is str:
            return item in allowed_strings
        if type(item) is tuple:
            return len(item) <= 24 and all(finite(row, depth + 1) for row in item)
        if type(item) is dict:
            return len(item) <= 32 and set(item) <= allowed_keys and all(
                finite(row, depth + 1) for row in item.values())
        return False
    if type(value['events']) is not tuple or len(value['events']) > 24 or not finite(value['events']):
        raise ValueError('trace_events')
    for event in value['events']:
        if (type(event) is not dict or set(event) != {'kind', 'code', 'module', 'function', 'line'} or
                type(event['line']) is not int or not 1 <= event['line'] <= 10000):
            raise ValueError('trace_event_fields')
    if value['terminal'] is not None and (type(value['terminal']) is not dict or not finite(value['terminal'])):
        raise ValueError('trace_terminal')
    if value['overflow_unknown'] and not value['trace_unknown']:
        raise ValueError('trace_overflow_unknown')
    return value



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    mode = 'device' if args.check_device else 'source'
    out = BASE / 'results' / ('receive-handoff-compat-v2-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, helpers, program = {}, None, None
    report = dict(schema='p011-receive-handoff-compat-v2', mode=mode, passed=False,
        source_checked=False, source_preserved=False, diagnostic_complete=False, device_invoked=False,
        host_exit='NOT_RUN', remote_exit='NOT_RUN', host_error=None, device_outcome='NOT_RUN',
        old_v1_runtime_modified=False, old_runtime_graph_modified=False, old_tests_replayed=0,
        runtime_v2_selected=True, runtime_v2_bytes=RUNTIME_V2[1], runtime_v2_sha256=RUNTIME_V2[2],
        old_graph_ast_replayed=False, source_runtime_graph_executed=False,
        trace_source_bytes=TRACE[1], trace_source_sha256=TRACE[2], trace_result=None,
        compatibility_test_executed=False, old_phone_runtime_modified=False,
        graph_derived=True, changed_business_role_count=1, changed_payload_role_count=6,
        changed_payload_roles_from_v1=5, frozen_handoff_reused=True,
        ordinary_private_executor_shared=True, private_changed_role_count=1,
        derived_source_count=0, exact_derivation_verified=False,
        automatic_receive_action_requested=args.check_device, http_action_requested=False,
        ui_requested=False, stock_ui_taken_over=False, guardian_requested=False,
        consent_accept_requested=False, scan_requested=False, send_requested=False,
        phone_tested=False, file_transfer_verified=False, full_network_restore_verified=False,
        original_activity_seconds=600, original_cleanup_seconds=60, preparation_max_seconds=15,
        phone_opportunity_seconds=45, observation_max_seconds=60,
        live_ready_forwarded=False, phone_discovery_user_confirmed=False,
        remote_alarm_seconds=780, host_timeout_seconds=790)
    try:
        raw = (BASE / DIAGNOSTIC[0]).read_bytes()
        if len(raw) != DIAGNOSTIC[1] or digest(raw) != DIAGNOSTIC[2]:
            raise ValueError('diagnostic_pin')
        diagnostic = types.ModuleType('fixed_startup_diagnostic_v2_definitions')
        diagnostic.__file__ = str(BASE / DIAGNOSTIC[0])
        exec(compile(raw, diagnostic.__file__, 'exec'), diagnostic.__dict__)
        original, original_raw = diagnostic.load_definition(COMPAT, 'fixed_receive_compat_definitions')
        v1, v1_raw = diagnostic.load_definition(diagnostic.V1_HOST, 'fixed_advertise_v1_definitions')
        helpers, bootstrap_raw = original.load_checker()
        def retain(path, raw):
            if path in inputs:
                if inputs[path] != raw:
                    raise ValueError('shared_input_changed')
                return
            inputs[path] = raw
            saved = out / 'private-inputs' / path
            saved.parent.mkdir(parents=True, exist_ok=True)
            write_new(saved, raw)
        retain(DIAGNOSTIC[0], raw); retain(COMPAT[0], original_raw)
        retain(original.ORIGINAL[0], original.ORIGINAL_RAW)
        retain(original.BASE_ORIGINAL[0], original.BASE_ORIGINAL_RAW)
        retain(diagnostic.V1_HOST[0], v1_raw); retain(original.CHECKER[0], bootstrap_raw)
        for pin in (original.MANIFEST, original.PRIVATE_MANIFEST, original.RUNNER, original.TRANSPORT,
                    v1.SMOKE, diagnostic.INNER, RUNTIME_V2, TRACE, PHONE_HOST,
                    original.ORIGINAL_MANIFEST) + original.ORIGIN_SOURCE_PINS:
            retain(pin[0], helpers.read_fixed(pin[0], pin[1:]))
        payload = (original.manifest_rows(inputs[original.MANIFEST[0]]) + original.HELPERS +
                   original.manifest_rows(inputs[original.PRIVATE_MANIFEST[0]], private=True) +
                   (original.WPA, original.MONITOR))
        if len(payload) != 75 or len({row[0] for row in payload}) != 75 or sum(row[2] for row in payload) > 4194304:
            raise ValueError('payload_budget')
        for name, path, size, sha in payload:
            retain(path, helpers.read_fixed(path, (size, sha)))
        for path in (SELF,) + CMDS + (TEST_SOURCE,):
            retain(path, helpers.read_fixed(path))
        # Parse only this NEW host and the NEW composition, not old graph/tests.
        ast.parse(inputs[SELF].decode('ascii'))
        ast.parse(inputs[TEST_SOURCE].decode('ascii'))
        derived = original.verify_inputs(inputs)
        report.update(derived_source_count=derived, exact_derivation_verified=True)
        program = make_source(original, v1, diagnostic, helpers, inputs, payload)
        ast.parse(program.decode('ascii'), feature_version=(3, 5))
        write_new(out / 'private-advertise-target.py', program)
        write_new(out / 'private-inputs.json', (json.dumps({path: dict(bytes=len(raw), sha256=digest(raw))
            for path, raw in inputs.items()}, sort_keys=True, indent=2) + '\n').encode('ascii'))
        report.update(source_checked=True, source_count=len(inputs), payload_role_count=75,
            target_bytes=len(program), target_sha256=digest(program),
            target_max_line_bytes=max(map(len, program.splitlines())))
        if args.check_device:
            transport = helpers.load_transport(inputs[original.TRANSPORT[0]])
            adb = transport.Adb(private)
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(780);'
                'exec(sys.stdin.buffer.read(' + str(len(program)) + '))" p011-receive-handoff-compat-v2; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True
            print('PHONE_DISCOVERY_LOG_DIR=' + str(out), flush=True)
            raw, live_ready = load_phone()[0].dispatch_live(transport, adb, private, program, command, 790)
            report['live_ready_forwarded'] = len(live_ready) == 1
            report['remote_exit'] = v1.exit_marker(raw)
            report['trace_result'] = parse_trace(diagnostic, raw)
            remote, component, smoke, projection, missing, busy, window = load_phone()[0].parse_observation(
                original, v1, diagnostic, helpers, raw)
            report.update(diagnostic_complete=True, smoke_complete=smoke['complete'], reason=smoke['reason'],
                trial_absent_startup_branch=missing, original_component_complete=component['complete'],
                inner_error_projection=projection, original_inner_error_available=projection['reason'] == 'observed',
                observation_lock_busy_count=busy, phone_window=window,
                device_outcome='FAIL_STARTUP_BEFORE_RECEIVE' if missing else
                    'PHONE_DISCOVERY_OPPORTUNITY_PASS' if smoke['complete'] else 'PHONE_DISCOVERY_OPPORTUNITY_FAIL')
            for key, value in smoke['flags'].items():
                report[key] = value
            if smoke['terminal'] is not None:
                for key, value in smoke['terminal'].items():
                    report['terminal_' + key] = value
            if report.get('terminal_handoff_received') is True:
                # Classification only: the frozen window deliberately cancels.
                # Original passed/closed/pending predicates below are unchanged.
                report['device_outcome'] = 'HANDOFF_CAPTURED_CANCELLED'
            for key, value in component.items():
                report['component_' + key] = value
            write_new(out / 'private-observation.json', (json.dumps(dict(smoke=smoke, inner=projection),
                sort_keys=True, indent=2) + '\n').encode('ascii'))
    except Exception as error:
        report['host_error'] = type(error).__name__
        write_new(private / 'host-error.txt', traceback.format_exc().encode('utf-8'))
    finally:
        prefix = private / '01-phone-discovery'
        for tag in ('stdout', 'stderr'):
            path = Path(str(prefix) + '.' + tag + '.raw')
            if path.exists():
                raw = path.read_bytes(); report[tag + '_bytes'] = len(raw); report[tag + '_sha256'] = digest(raw)
                if tag == 'stdout':
                    value = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
                    rows = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', value, re.M)
                    report['remote_exit'] = int(rows[0]) if len(rows) == 1 else 'UNKNOWN'
        path = Path(str(prefix) + '.host-exit')
        if path.exists():
            value = path.read_text(encoding='ascii').strip()
            report['host_exit'] = int(value) if re.fullmatch(r'-?\d+', value) else 'TIMEOUT'
        write_new(private / 'remote-exit', (str(report['remote_exit']) + '\n').encode('ascii'))
        try:
            report['source_preserved'] = bool(inputs) and helpers is not None and all(
                helpers.read_fixed(path) == raw and (out / 'private-inputs' / path).read_bytes() == raw
                for path, raw in inputs.items()) and program is not None and (
                    out / 'private-advertise-target.py').read_bytes() == program
        except Exception:
            report['source_preserved'] = False
    report['passed'] = (report['source_checked'] and report['source_preserved'] and report['host_error'] is None and
        (not args.check_device or report['host_exit'] == 0 and report.get('stderr_bytes') == 0 and
         report['remote_exit'] == 0 and report.get('smoke_complete') is True and
         report['trace_result'] is not None and report['trace_result']['thread_trace_installed'] is True and
         report['trace_result']['thread_trace_hook_restored'] is True and report['trace_result']['trace_unknown'] is False))
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Frozen v1 and original graphs remain unchanged. v2 creates exactly six source derivatives: '
        b'Executor changes only its fixed startup runtime35 directory; StateBridge/Factory/Boot/Owner/Session '
        b'propagate independent root and exact ordinary/private pins. CLIENT roots and token paths stay original. '
        b'Handoff known-field projection is reused byte-for-byte from frozen v1. Ordinary roles changed from '
        b'v1: five; private roles: Executor only, other34 original; original helper/GO/assets and phone/trace '
        b'bytes stay original. No __file__ alias, broader path or runtime predicate is introduced. '
        b'Original cancel/600+60/caps/finalizer/pending remain unchanged. No accept/send/UI/record cleanup. '
        b'Trace DATA do not prove restoration. HANDOFF_CAPTURED_CANCELLED is only a classification of validated '
        b'terminal_handoff_received, never pass/decryption/Bridge/file/restore authority. Default PC SOURCE '
        b'checks only six exact derivatives, new HOST/test syntax and new composition Python3.5/budget. '
        b'The two new HOST tests extract the actual Executor directory predicate and exercise the new manifest '
        b'parser; this entry retains but does not run them. Frozen capture tests are not replayed.\n')
    write_new(out / 'result.json', public); write_new(out / 'README.txt', readme)
    bundle_path = out / 'public-result.zip'
    with zipfile.ZipFile(bundle_path, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public); bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(bundle_path) as bundle:
        if bundle.namelist() != ['result.json', 'README.txt'] or bundle.read('result.json') != public or bundle.read('README.txt') != readme:
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], mode=mode, device_outcome=report['device_outcome'],
        result_dir=str(out), public_result_zip=str(bundle_path), zip_sha256=digest(bundle_path.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
