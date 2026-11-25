"""Default PC SOURCE; explicit --check-device starts one real receiver advert.

No Qt/stock takeover, HTTP action, consent, scan, send or fabricated ACK.
Frozen 75-role definitions are byte-pinned, not HOST executed or AST replayed.
"""
import argparse
import ast
import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import secrets
import traceback
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]
ORIGINAL = ('host/device_receive_interactive_v1_check.py', 51764,
            '85744bf1c282b55b997911222f9dfb83b5f3ffdb9badc956017ef551521c58ca')
SMOKE = ('candidate/receive-advertise-smoke-v1/runtime/advertise_smoke_session.py',
         13702, '034d3914bc0be2e17d0a9a015e6957126f882c6cf5bcbf8f4f3765e0717afc93')
SELF = 'host/device_receive_advertise_smoke_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_ADVERTISE_SMOKE_V1_CHECK.cmd', 'TEST_MTA_RECEIVE_ADVERTISE_SMOKE_V1.cmd')
FLAGS = ('start_called', 'start_returned', 'receive_ready', 'advertising_seen', 'listen_seen',
         'peer_activity_seen', 'stop_called', 'stop_returned', 'native_failure_seen',
         'late_peer_activity_seen', 'closure_verified', 'baseline_verified', 'resource_pending')
OBS_BOOL = ('discoverable', 'advertising', 'handoff_received', 'bridge_started', 'request_present',
            'peer_activity', 'native_failure', 'worker_alive', 'helper_retained')
TERMINAL_BOOL = ('operation_retained', 'session_retained', 'worker_alive', 'helper_retained',
    'helper_reader_alive', 'helper_reaped', 'helper_closed', 'key_retained', 'key_closed',
    'bridge_retained', 'bridge_started', 'handoff_received', 'parent_retained', 'deployment_retained',
    'network_before_present', 'network_after_present', 'network_zero_known', 'network_verified',
    'receive_extra_verified', 'radio_restore_pending', 'wifi_restore_pending')
REASONS = ('not_started', 'receive_refused', 'advert_not_observed', 'peer_activity_cancelled',
           'native_operation_failed', 'advertising_observed', 'operation_unknown')
TARGET = r'''
ERROR_MODULES=ERROR_MODULES+('fixed_receive_advertise_smoke',)
session=types.ModuleType('fixed_startup_readonly_diagnostic')
session.__file__='<fixed-formal-receive-service-stdin>'
exec(runner_raw,session.__dict__)
smoke=types.ModuleType('fixed_receive_advertise_smoke')
smoke.__file__='<fixed-receive-advertise-smoke-stdin>'
exec(fixed_decode(SMOKE_ENCODED,SMOKE_PIN[0],SMOKE_PIN[1]),smoke.__dict__)
result=smoke.run_fixed(session,artifacts)
detail=fixed_error_details(smoke._RETAINED.failures)
if detail:print('ERROR_DETAIL='+repr(detail))
print('TRIAL_START='+repr(result['trials']['start']))
print('TRIAL_END='+repr(result['trials']['end']))
print('RESULT='+repr(result['component']))
print('SMOKE_RESULT='+repr(result))
print('MTA_REMOTE_OK')
raise SystemExit(0 if result['complete'] else 1)
'''


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise OSError('short_write')


def exit_marker(raw):
    value = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    rows = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', value, re.M)
    return int(rows[0]) if len(rows) == 1 else 'UNKNOWN'


def make_source(original, helpers, inputs, payload):
    old = original.make_source(helpers, inputs, payload, False)
    tail = original.TARGET_SERVICE.encode('ascii')
    if not old.endswith(tail):
        raise ValueError('original_envelope_changed')
    added = ('SMOKE_PIN=' + repr(SMOKE[1:]) + '\nSMOKE_ENCODED=(\n' +
             original._short_chunks(helpers, inputs[SMOKE[0]]) + '\n)\n' + TARGET).encode('ascii')
    program = old[:-len(tail)] + added
    if len(program) > 2097152 or any(len(line) > 256 for line in program.splitlines()):
        raise ValueError('target_source_budget')
    return program


def parse_smoke(raw, component, remote, trials):
    text = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    rows = re.findall(r'^SMOKE_RESULT=(.*)$', text, re.M)
    if len(rows) != 1:
        raise ValueError('smoke_result_unknown')
    value = ast.literal_eval(rows[0])
    if (type(value) is not dict or set(value) != {'scope', 'complete', 'reason', 'flags',
            'observations', 'terminal', 'trials', 'component'} or
            value['scope'] != 'receive-advertise-cancel-only-v1' or type(value['complete']) is not bool or
            value['reason'] not in REASONS or value['component'] != component or
            type(value['flags']) is not dict or set(value['flags']) != set(FLAGS) or
            any(type(item) is not bool for item in value['flags'].values()) or
            type(value['observations']) is not tuple or len(value['observations']) > 160 or
            value['trials'] != trials or
            value['terminal'] is not None and type(value['terminal']) is not dict or
            remote != (0 if value['complete'] else 1)):
        raise ValueError('smoke_result_fields')
    def counts_valid(row):
        return (type(row) is tuple and len(row) == 6 and
                all(type(item) is int and 0 <= item <= 1000000 for item in row))
    for row in value['observations']:
        if (type(row) is not dict or set(row) != set(OBS_BOOL + ('stage', 'state', 'event_counts', 'elapsed_seconds')) or
                any(type(row[key]) is not bool for key in OBS_BOOL) or
                any(type(row[key]) is not str or re.fullmatch(r'[a-z_]{1,40}', row[key]) is None for key in ('stage', 'state')) or
                not counts_valid(row['event_counts']) or type(row['elapsed_seconds']) is not float or
                not math.isfinite(row['elapsed_seconds']) or not 0 <= row['elapsed_seconds'] <= 60):
            raise ValueError('smoke_observation_fields')
    ended = value['terminal']
    if ended is not None and (set(ended) != set(TERMINAL_BOOL + ('event_counts',)) or
            any(type(ended[key]) is not bool for key in TERMINAL_BOOL) or not counts_valid(ended['event_counts'])):
        raise ValueError('smoke_terminal_fields')
    if value['complete'] and (not all(value['flags'][name] for name in
            ('start_called', 'start_returned', 'receive_ready', 'advertising_seen', 'listen_seen',
             'stop_called', 'stop_returned', 'closure_verified', 'baseline_verified')) or
            any(value['flags'][name] for name in ('peer_activity_seen', 'late_peer_activity_seen', 'native_failure_seen', 'resource_pending')) or
            value['reason'] != 'advertising_observed' or not value['observations'] or
            value['terminal'] is None or not value['terminal'].get('helper_closed') or
            not value['terminal'].get('network_zero_known') or value['terminal'].get('bridge_started') is not False):
        raise ValueError('smoke_complete_fields')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    mode = 'device' if args.check_device else 'source'
    out = BASE / 'results' / ('receive-advertise-smoke-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, helpers, program = {}, None, None
    report = dict(schema='p011-receive-advertise-cancel-smoke-v1', mode=mode, passed=False,
        source_checked=False, source_preserved=False, device_invoked=False, observation_received=False,
        source_runtime_graph_executed=False, old_graph_ast_replayed=False, old_tests_replayed=0,
        old_checker_main_called=False, original_runner_run_called=False, original_component_complete=None,
        host_exit='NOT_RUN', remote_exit='NOT_RUN', host_error=None, scope='receive-advertise-cancel-only-v1',
        automatic_receive_action_requested=args.check_device, http_action_requested=False,
        ui_requested=False, stock_ui_taken_over=False, guardian_requested=False, consent_accept_requested=False,
        scan_requested=False, send_requested=False, phone_tested=False, file_transfer_verified=False,
        full_network_restore_verified=False, fake_native_events=False, fake_ack=False,
        original_activity_seconds=60, original_cleanup_seconds=60, observation_max_seconds=15,
        remote_alarm_seconds=240, host_timeout_seconds=250)
    try:
        raw = (BASE / ORIGINAL[0]).read_bytes()
        if len(raw) != ORIGINAL[1] or digest(raw) != ORIGINAL[2]:
            raise ValueError('original_pin')
        original = types.ModuleType('fixed_receive_interactive_host_definitions')
        original.__file__ = str(BASE / ORIGINAL[0])
        exec(compile(raw, original.__file__, 'exec'), original.__dict__)
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
        retain(ORIGINAL[0], raw); retain(original.CHECKER[0], bootstrap_raw)
        for pin in (original.MANIFEST, original.PRIVATE_MANIFEST, original.RUNNER, original.TRANSPORT, SMOKE):
            retain(pin[0], helpers.read_fixed(pin[0], pin[1:]))
        payload = (original.manifest_rows(inputs[original.MANIFEST[0]]) + original.HELPERS +
                   original.manifest_rows(inputs[original.PRIVATE_MANIFEST[0]], private=True) +
                   (original.WPA, original.MONITOR))
        if len(payload) != 75 or len({row[0] for row in payload}) != 75 or sum(row[2] for row in payload) > 4194304:
            raise ValueError('payload_budget')
        for name, path, size, sha in payload:
            retain(path, helpers.read_fixed(path, (size, sha)))
        for path in (SELF,) + CMDS:
            retain(path, helpers.read_fixed(path))
        # Only the two NEW sources and one generated envelope are parsed here.
        ast.parse(inputs[SMOKE[0]].decode('ascii'), feature_version=(3, 5))
        ast.parse(inputs[SELF].decode('ascii'))
        program = make_source(original, helpers, inputs, payload)
        ast.parse(program.decode('ascii'), feature_version=(3, 5))
        write_new(out / 'private-service-target.py', program)
        write_new(out / 'private-inputs.json', (json.dumps({path: dict(bytes=len(raw), sha256=digest(raw))
            for path, raw in inputs.items()}, sort_keys=True, indent=2) + '\n').encode('ascii'))
        report.update(source_checked=True, source_count=len(inputs), payload_role_count=len(payload),
            target_bytes=len(program), target_sha256=digest(program),
            target_max_line_bytes=max(map(len, program.splitlines())))
        if args.check_device:
            transport = helpers.load_transport(inputs[original.TRANSPORT[0]])
            adb = transport.Adb(private)
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(240);'
                'exec(sys.stdin.buffer.read(' + str(len(program)) + '))" p011-receive-advertise-smoke-v1; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True
            raw = adb.run('advertise-smoke', ['shell', command], timeout=250, input_data=program)
            report['remote_exit'] = exit_marker(raw)
            remote, component = helpers.parse_result(raw)
            smoke = parse_smoke(raw, component, remote, original.parse_trial_facts(raw))
            report.update(observation_received=True, smoke_complete=smoke['complete'], reason=smoke['reason'],
                          original_component_complete=component['complete'])
            for key, value in smoke['flags'].items():
                report[key] = value
            if smoke['terminal'] is not None:
                for key, value in smoke['terminal'].items():
                    report['terminal_' + key] = value
            write_new(out / 'private-observation.json', (json.dumps(smoke, sort_keys=True, indent=2) + '\n').encode('ascii'))
    except Exception as error:
        report['host_error'] = type(error).__name__
        write_new(private / 'host-error.txt', traceback.format_exc().encode('utf-8'))
    finally:
        prefix = private / '01-advertise-smoke'
        for tag in ('stdout', 'stderr'):
            path = Path(str(prefix) + '.' + tag + '.raw')
            if path.exists():
                raw = path.read_bytes()
                report[tag + '_bytes'] = len(raw); report[tag + '_sha256'] = digest(raw)
                if tag == 'stdout':
                    report['remote_exit'] = exit_marker(raw)
        path = Path(str(prefix) + '.host-exit')
        if path.exists():
            value = path.read_text(encoding='ascii').strip()
            report['host_exit'] = int(value) if re.fullmatch(r'-?\d+', value) else 'TIMEOUT'
        write_new(private / 'remote-exit', (str(report['remote_exit']) + '\n').encode('ascii'))
        try:
            report['source_preserved'] = bool(inputs) and helpers is not None and all(
                helpers.read_fixed(path) == raw and (out / 'private-inputs' / path).read_bytes() == raw
                for path, raw in inputs.items()) and program is not None and (
                    out / 'private-service-target.py').read_bytes() == program
        except Exception:
            report['source_preserved'] = False
    report['passed'] = (report['source_checked'] and report['source_preserved'] and report['host_error'] is None and
        (not args.check_device or report['host_exit'] == 0 and report.get('stderr_bytes') == 0 and
         report['remote_exit'] == 0 and report.get('smoke_complete') is True))
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Default PC SOURCE only. Explicit --check-device invokes one original receive action and real '
        b'listen/advert events for at most 15 seconds, using unchanged fixed75 and original activity60/cleanup60. '
        b'No Qt, stock takeover, guardian, HTTP action, accept, scan, send or fake ACK. Initial connecting is '
        b'not a handoff. Actual handoff/Bridge/request causes immediate cancel; original finalizers handle '
        b'any real Parent/F/network use, never a synthetic zero branch. All unknowns remain pending. '
        b'Original closed-policy run() is not called and its raw complete=False is preserved. New smoke '
        b'PASS requires actual advertising, no phone branch, original actors closed and baseline unchanged. '
        b'This is not phone interoperability, TLS/file receive, whole-system zero RF or full network restore '
        b'proof. Private raw logs, generated program and inputs stay local; inspect before sharing.\n')
    write_new(out / 'result.json', public); write_new(out / 'README.txt', readme)
    bundle_path = out / 'public-result.zip'
    with zipfile.ZipFile(bundle_path, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public); bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(bundle_path) as bundle:
        if bundle.namelist() != ['result.json', 'README.txt'] or bundle.read('result.json') != public or bundle.read('README.txt') != readme:
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out),
        public_result_zip=str(bundle_path), zip_sha256=digest(bundle_path.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
