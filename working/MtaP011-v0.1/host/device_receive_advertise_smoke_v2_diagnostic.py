"""Independent PC SOURCE / existing-v1 diagnosis / startup-only device entry.

The original v1 FAIL and raw files are immutable. This entry never invokes
discover_start, scan, send, UI, consent or guardian. Device mode is explicit.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import traceback
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_advertise_smoke_v2_diagnostic.py'
CMD = 'HOST_MTA_RECEIVE_STARTUP_DIAGNOSTIC_V2.cmd'
ORIGINAL = ('host/device_receive_interactive_v1_check.py', 51764,
            '85744bf1c282b55b997911222f9dfb83b5f3ffdb9badc956017ef551521c58ca')
V1_HOST = ('host/device_receive_advertise_smoke_v1_check.py', 15793,
           '7724e54273b042673cc9e9a1a2ba13185fab6db704dad7056079141f7d075041')
INNER = ('candidate/receive-startup-inner-v1/runtime/startup_inner_error.py', 4565,
         'e74c02d2b5d52d9b2a23dc88f0a66ca8956a15837de9f0f8a061d642343a6e4b')
V1_RESULT = 'results/receive-advertise-smoke-v1-device-20261004-231318-830d3b8c'
V1_STDOUT = (2024059, 'd0fdba384c836de978a75e77d900c45e4b958beb064afe46bc130cf4ecfc939d')
TARGET = r'''
session=types.ModuleType('fixed_startup_readonly_diagnostic')
session.__file__='<fixed-formal-receive-service-stdin>'
exec(runner_raw,session.__dict__)
inner=types.ModuleType('fixed_startup_inner_error')
inner.__file__='<fixed-startup-inner-error-stdin>'
exec(fixed_decode(INNER_ENCODED,INNER_PIN[0],INNER_PIN[1]),inner.__dict__)
component=session.run_fixed(artifacts,False,receive_trial_requested=True)
retained=session._RETAINED
print('TRIAL_START='+repr(retained.trial_start_facts))
print('TRIAL_END='+repr(retained.trial_end_facts))
detail=fixed_error_details(retained.failures)
if detail:print('ERROR_DETAIL='+repr(detail))
print('BASELINE_INNER_ERROR_DETAIL='+repr(inner.project_original(retained)))
print('RESULT='+repr(component))
print('MTA_REMOTE_OK')
raise SystemExit(0 if component['complete'] else 1)
'''


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise OSError('short_write')


def load_definition(pin, name):
    raw = (BASE / pin[0]).read_bytes()
    if len(raw) != pin[1] or digest(raw) != pin[2]:
        raise ValueError('definition_pin')
    module = types.ModuleType(name)
    module.__file__ = str(BASE / pin[0])
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module, raw


def derived_text(raw):
    return raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')


def one_literal(raw, tag):
    rows = re.findall(r'^' + tag + r'=(.*)$', derived_text(raw), re.M)
    if len(rows) != 1:
        raise ValueError('diagnostic_marker_unknown')
    return ast.literal_eval(rows[0])


def parse_trials(original, raw, component):
    start = one_literal(raw, 'TRIAL_START')
    end = one_literal(raw, 'TRIAL_END')
    if start is not None or end is not None:
        # No mixed None/data relaxation. Ordinary trial DATA retains the exact
        # old field/type/reason validator, including malformed-field refusal.
        return original.parse_trial_facts(raw), False
    if (component['complete'] is not False or component['owner_started'] is not False or
            component['startup_readonly_called'] is not True or
            any(component[name] is not False for name in
                ('startup_readonly_verified', 'startup_baseline_collected', 'startup_status_verified')) or
            component['http_request_count'] != 0 or component['client_socket_count'] != 0):
        raise ValueError('missing_trial_not_startup_failure')
    return dict(start=None, end=None), True


def original_closed(helpers, component):
    # Failure and physical closure remain different facts, never PASS aliases.
    return (all(component[name] is True for name in helpers.COMMON) and
        all(component[name] is True for name in ('owner_close_called', 'owner_resources_closed',
            'startup_resources_closed', 'capability_actors_closed')) and
        component['resource_pending'] is False and component['staging_pending'] is False and
        component['runner_opened_fd_count'] == component['runner_closed_fd_count'])


def validate_original_error(original, helpers, row):
    allowed = set(original.MODULE_NAMES + original.PRIVATE_MODULE_NAMES +
                  ('fixed_receive_advertise_smoke', 'fixed_startup_readonly_diagnostic',
                   'startup_readonly_private_owner', 'threading', 'socket', 'subprocess', 'types'))
    if (type(row) is not dict or set(row) != {'kind', 'code', 'errno', 'trace'} or
            type(row['kind']) is not str or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', row['kind']) is None or
            row['code'] not in set(helpers.REASONS + original.TRIAL_REASONS + ('unclassified',)) or
            row['errno'] is not None and (type(row['errno']) is not int or not 1 <= row['errno'] <= 4095) or
            type(row['trace']) is not tuple or len(row['trace']) > 32):
        raise ValueError('original_error_fields')
    for frame in row['trace']:
        if (type(frame) is not tuple or len(frame) != 3 or frame[0] not in allowed or
                type(frame[1]) is not str or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,95}', frame[1]) is None or
                type(frame[2]) is not int or not 1 <= frame[2] <= 1000000):
            raise ValueError('original_error_trace')


def parse_inner(original, raw):
    value = one_literal(raw, 'BASELINE_INNER_ERROR_DETAIL')
    if (type(value) is not dict or set(value) != {'reason', 'entries'} or
            value['reason'] not in ('observed', 'not_available', 'unknown') or
            type(value['entries']) is not tuple or len(value['entries']) > 8):
        raise ValueError('inner_projection_unknown')
    allowed = set(original.PRIVATE_MODULE_NAMES) | {'mta_client_startup_readonly'}
    for row in value['entries']:
        if (type(row) is not dict or set(row) != {'kind', 'errno', 'trace'} or
                type(row['kind']) is not str or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', row['kind']) is None or
                row['errno'] is not None and (type(row['errno']) is not int or not 1 <= row['errno'] <= 4095) or
                type(row['trace']) is not tuple or len(row['trace']) > 32):
            raise ValueError('inner_projection_fields')
        for frame in row['trace']:
            if (type(frame) is not tuple or len(frame) != 3 or frame[0] not in allowed or
                    type(frame[1]) is not str or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,95}', frame[1]) is None or
                    type(frame[2]) is not int or not 1 <= frame[2] <= 1000000):
                raise ValueError('inner_projection_trace')
    if (value['reason'] == 'observed') is not bool(value['entries']):
        raise ValueError('inner_projection_reason')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--derive-existing', action='store_true')
    modes.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    mode = 'derive-existing' if args.derive_existing else 'device-startup' if args.check_device else 'source'
    out = BASE / 'results' / ('receive-startup-diagnostic-v2-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, helpers, program = {}, None, None
    report = dict(schema='p011-receive-startup-diagnostic-v2', mode=mode, passed=False,
        diagnostic_complete=False, device_outcome='NOT_RUN', device_passed=False,
        device_invoked=False, source_checked=False, source_preserved=False,
        original_v1_fail_preserved=True, old_runtime_graph_modified=False,
        source_runtime_graph_executed=False, old_graph_ast_replayed=False, old_tests_replayed=0,
        host_exit='NOT_RUN', remote_exit='NOT_RUN', host_error=None,
        automatic_receive_action_requested=False, http_action_requested=False, ui_requested=False,
        scan_requested=False, send_requested=False, consent_accept_requested=False,
        original_activity_seconds=60, original_cleanup_seconds=60, remote_alarm_seconds=240,
        host_timeout_seconds=250, original_inner_error_available=False)
    try:
        original, original_raw = load_definition(ORIGINAL, 'fixed_interactive_definitions')
        v1, v1_raw = load_definition(V1_HOST, 'fixed_advertise_v1_definitions')
        helpers, bootstrap_raw = original.load_checker()
        def retain(path, raw):
            if path in inputs:
                if inputs[path] != raw:
                    raise ValueError('source_changed')
                return
            inputs[path] = raw
            saved = out / 'private-inputs' / path
            saved.parent.mkdir(parents=True, exist_ok=True)
            write_new(saved, raw)
        retain(ORIGINAL[0], original_raw); retain(V1_HOST[0], v1_raw)
        retain(original.CHECKER[0], bootstrap_raw)
        for path in (SELF, CMD, INNER[0]):
            raw = helpers.read_fixed(path, INNER[1:] if path == INNER[0] else None)
            retain(path, raw)
        ast.parse(inputs[SELF].decode('ascii'))
        ast.parse(inputs[INNER[0]].decode('ascii'), feature_version=(3, 5))
        if args.derive_existing:
            source = BASE / V1_RESULT
            raw = (source / 'private-raw/01-advertise-smoke.stdout.raw').read_bytes()
            if len(raw) != V1_STDOUT[0] or digest(raw) != V1_STDOUT[1]:
                raise ValueError('existing_stdout_changed')
            stderr = (source / 'private-raw/01-advertise-smoke.stderr.raw').read_bytes()
            host_exit = (source / 'private-raw/01-advertise-smoke.host-exit').read_bytes()
            old_report = json.loads((source / 'result.json').read_text(encoding='ascii'))
            if stderr != b'' or host_exit.strip() != b'0' or old_report['passed'] is not False:
                raise ValueError('existing_result_changed')
            remote, component = helpers.parse_result(raw)
            trials, missing = parse_trials(original, raw, component)
            smoke = v1.parse_smoke(raw, component, remote, trials)
            if (not missing or remote != 1 or smoke['complete'] is not False or smoke['reason'] != 'operation_unknown' or
                    smoke['observations'] != () or smoke['terminal'] is not None or
                    any(smoke['flags'][name] is not False for name in
                        ('start_called', 'start_returned', 'receive_ready', 'advertising_seen', 'listen_seen',
                         'peer_activity_seen', 'late_peer_activity_seen', 'stop_called', 'stop_returned'))):
                raise ValueError('existing_failure_not_pre_receive')
            detail = one_literal(raw, 'ERROR_DETAIL')
            if type(detail) is not tuple or not detail or len(detail) > 16:
                raise ValueError('existing_error_unknown')
            for row in detail:
                validate_original_error(original, helpers, row)
            for name, data in (('stdout.raw', raw), ('stderr.raw', stderr), ('host-exit', host_exit)):
                write_new(private / name, data)
            write_new(out / 'private-observation.json', (json.dumps(dict(smoke=smoke, errors=detail),
                sort_keys=True, indent=2) + '\n').encode('ascii'))
            report.update(diagnostic_complete=True, device_outcome='FAIL_STARTUP_BEFORE_RECEIVE',
                host_exit=0, remote_exit=remote, original_host_parser_failed=True,
                trial_absent_startup_branch=True, original_owner_started=component['owner_started'],
                original_smoke_complete=smoke['complete'], original_start_called=smoke['flags']['start_called'],
                original_closed_baseline_verified=original_closed(helpers, component),
                original_resource_pending=component['resource_pending'], original_staging_pending=component['staging_pending'],
                original_opened_fds=component['runner_opened_fd_count'], original_closed_fds=component['runner_closed_fd_count'],
                original_error_details=detail, stdout_bytes=len(raw), stdout_sha256=digest(raw), stderr_bytes=0)
        else:
            for pin in (original.MANIFEST, original.PRIVATE_MANIFEST, original.RUNNER, original.TRANSPORT):
                retain(pin[0], helpers.read_fixed(pin[0], pin[1:]))
            payload = (original.manifest_rows(inputs[original.MANIFEST[0]]) + original.HELPERS +
                original.manifest_rows(inputs[original.PRIVATE_MANIFEST[0]], private=True) + (original.WPA, original.MONITOR))
            if len(payload) != 75 or len({row[0] for row in payload}) != 75 or sum(row[2] for row in payload) > 4194304:
                raise ValueError('payload_budget')
            for name, path, size, sha in payload:
                retain(path, helpers.read_fixed(path, (size, sha)))
            old = original.make_source(helpers, inputs, payload, False)
            tail = original.TARGET_SERVICE.encode('ascii')
            if not old.endswith(tail):
                raise ValueError('original_envelope_changed')
            added = ('INNER_PIN=' + repr(INNER[1:]) + '\nINNER_ENCODED=(\n' +
                original._short_chunks(helpers, inputs[INNER[0]]) + '\n)\n' + TARGET).encode('ascii')
            program = old[:-len(tail)] + added
            if len(program) > 2097152 or any(len(line) > 256 for line in program.splitlines()):
                raise ValueError('target_source_budget')
            ast.parse(program.decode('ascii'), feature_version=(3, 5))
            write_new(out / 'private-startup-target.py', program)
            report.update(source_checked=True, payload_role_count=75, target_bytes=len(program),
                          target_sha256=digest(program), target_max_line_bytes=max(map(len, program.splitlines())))
            if args.check_device:
                transport = helpers.load_transport(inputs[original.TRANSPORT[0]])
                adb = transport.Adb(private)
                command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(240);'
                    'exec(sys.stdin.buffer.read(' + str(len(program)) + '))" p011-receive-startup-inner-v2; '
                    'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
                report['device_invoked'] = True
                raw = adb.run('startup-inner', ['shell', command], timeout=250, input_data=program)
                remote, component = helpers.parse_result(raw)
                trials, missing = parse_trials(original, raw, component)
                projection = parse_inner(original, raw)
                report.update(diagnostic_complete=True, remote_exit=remote,
                    device_outcome='FAIL_STARTUP_BEFORE_RECEIVE' if missing else 'STARTUP_FAILURE_NOT_REPRODUCED',
                    trial_absent_startup_branch=missing, original_component_complete=component['complete'],
                    startup_failure_reproduced=missing,
                    original_closed_baseline_verified=original_closed(helpers, component),
                    original_resource_pending=component['resource_pending'],
                    original_inner_error_available=projection['reason'] == 'observed', inner_error_projection=projection)
                write_new(out / 'private-observation.json', (json.dumps(dict(component=component, trials=trials,
                    inner=projection), sort_keys=True, indent=2) + '\n').encode('ascii'))
    except Exception as error:
        report['host_error'] = type(error).__name__
        write_new(private / 'host-error.txt', traceback.format_exc().encode('utf-8'))
    finally:
        prefix = private / '01-startup-inner'
        for tag in ('stdout', 'stderr'):
            path = Path(str(prefix) + '.' + tag + '.raw')
            if path.exists():
                raw = path.read_bytes(); report[tag + '_bytes'] = len(raw); report[tag + '_sha256'] = digest(raw)
                if tag == 'stdout':
                    rows = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived_text(raw), re.M)
                    report['remote_exit'] = int(rows[0]) if len(rows) == 1 else 'UNKNOWN'
        path = Path(str(prefix) + '.host-exit')
        if path.exists():
            value = path.read_text(encoding='ascii').strip()
            report['host_exit'] = int(value) if re.fullmatch(r'-?\d+', value) else 'TIMEOUT'
        try:
            report['source_preserved'] = bool(inputs) and helpers is not None and all(
                helpers.read_fixed(path) == raw and (out / 'private-inputs' / path).read_bytes() == raw
                for path, raw in inputs.items()) and (program is None or (out / 'private-startup-target.py').read_bytes() == program)
        except Exception:
            report['source_preserved'] = False
    # A successfully parsed failure has diagnostic_complete=True, not PASS.
    # This entry makes no new receive/phone/advertisement success declaration.
    report['passed'] = (mode == 'source' and report['source_checked'] and report['source_preserved'] and
                        report['host_error'] is None)
    operation_ok = report['passed'] if mode == 'source' else (
        report['diagnostic_complete'] and report['source_preserved'] and report['host_error'] is None and
        report['host_exit'] == 0 and report.get('stderr_bytes') == 0 and report['remote_exit'] in (0, 1))
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'PC SOURCE by default. --derive-existing reads only the pinned first v1 raw FAIL; no device retry. '
        b'--check-device invokes original startup/close only, with unchanged fixed75/60+60; no receive advert, '
        b'scan/UI/accept/guardian or old graph mutation. Missing TRIAL is accepted only for actual startup '
        b'failure with original owner_startedFalse and zero client HTTP inventory; the historical v1 smoke '
        b'must additionally have start_calledFalse, no observations/terminal or advertising. Such records '
        b'remain FAIL. diagnostic_complete/exit0 mean parsing completed, never device PASS. New passive '
        b'projection reads original collect traceback local error only after original identity checks; '
        b'only exception kind/errno and trusted source locations are returned. No args, locals values, '
        b'paths, identities or credentials. Existing v1 raw lacks the inner exception and cannot recreate it.\n')
    write_new(out / 'result.json', public); write_new(out / 'README.txt', readme)
    bundle_path = out / 'public-result.zip'
    with zipfile.ZipFile(bundle_path, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public); bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(bundle_path) as bundle:
        if bundle.namelist() != ['result.json', 'README.txt'] or bundle.read('result.json') != public or bundle.read('README.txt') != readme:
            raise ValueError('zip_readback')
    print(json.dumps(dict(mode=mode, passed=report['passed'], diagnostic_complete=report['diagnostic_complete'],
        device_outcome=report['device_outcome'], device_passed=False, result_dir=str(out),
        public_result_zip=str(bundle_path), zip_sha256=digest(bundle_path.read_bytes())), sort_keys=True))
    return 0 if operation_ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
