"""Isolated lock-busy-retry runtime with same-run original error projection.

Default PC SOURCE. Only --check-device starts the authorized real one-shot
receive advert/cancel. Old sources/fixed75 and original 60+60/15 remain unchanged.
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
SELF = 'host/device_receive_advertise_smoke_v3_check.py'
CMDS = ('HOST_MTA_RECEIVE_ADVERTISE_SMOKE_V3_CHECK.cmd', 'TEST_MTA_RECEIVE_ADVERTISE_SMOKE_V3.cmd')
DIAGNOSTIC = ('host/device_receive_advertise_smoke_v2_diagnostic.py', 19645,
              'c33a0e73569ddac453230e0ba509955a4b08a84742633b021c433b8dc77d6201')
RUNTIME_V2 = ('candidate/receive-advertise-smoke-v2/runtime/advertise_smoke_session.py', 14451,
              '067c96a58c227960647eaa9f74fa964d220ba058afc92fe095d71b19f2d3385c')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise OSError('short_write')


def make_source(original, v1, diagnostic, helpers, inputs, payload):
    old = v1.make_source(original, helpers, inputs, payload)
    # Replace only the envelope runtime encoding; do not mutate old definitions
    # or any of the original 75 business payload roles.
    previous = ('SMOKE_PIN=' + repr(v1.SMOKE[1:]) + '\nSMOKE_ENCODED=(\n' +
                original._short_chunks(helpers, inputs[v1.SMOKE[0]]) + '\n)\n').encode('ascii')
    selected = ('SMOKE_PIN=' + repr(RUNTIME_V2[1:]) + '\nSMOKE_ENCODED=(\n' +
                original._short_chunks(helpers, inputs[RUNTIME_V2[0]]) + '\n)\n').encode('ascii')
    if old.count(previous) != 1:
        raise ValueError('v1_runtime_encoding_changed')
    old = old.replace(previous, selected)
    tail = v1.TARGET.encode('ascii')
    if not old.endswith(tail):
        raise ValueError('v1_envelope_changed')
    marker = 'result=smoke.run_fixed(session,artifacts)\n'
    if v1.TARGET.count(marker) != 1:
        raise ValueError('v1_call_changed')
    added = ('INNER_PIN=' + repr(diagnostic.INNER[1:]) + '\nINNER_ENCODED=(\n' +
             original._short_chunks(helpers, inputs[diagnostic.INNER[0]]) + '\n)\n')
    projection = ("inner=types.ModuleType('fixed_startup_inner_error')\n"
        "inner.__file__='<fixed-startup-inner-error-stdin>'\n"
        'exec(fixed_decode(INNER_ENCODED,INNER_PIN[0],INNER_PIN[1]),inner.__dict__)\n' + marker +
        "print('BASELINE_INNER_ERROR_DETAIL='+repr(inner.project_original(smoke._RETAINED)))\n"
        "print('OBSERVATION_LOCK_BUSY_COUNT='+repr(smoke._OBSERVATION_BUSY_COUNT))\n")
    program = old[:-len(tail)] + (added + v1.TARGET.replace(marker, projection)).encode('ascii')
    if len(program) > 2097152 or any(len(line) > 256 for line in program.splitlines()):
        raise ValueError('target_source_budget')
    return program


def parse_observation(original, v1, diagnostic, helpers, raw):
    remote, component = helpers.parse_result(raw)
    trials, missing = diagnostic.parse_trials(original, raw, component)
    smoke = v1.parse_smoke(raw, component, remote, trials)
    if missing and (remote != 1 or smoke['complete'] is not False or smoke['reason'] != 'operation_unknown' or
            smoke['observations'] != () or smoke['terminal'] is not None or
            any(smoke['flags'][name] is not False for name in
                ('start_called', 'start_returned', 'receive_ready', 'advertising_seen', 'listen_seen',
                 'peer_activity_seen', 'late_peer_activity_seen', 'stop_called', 'stop_returned'))):
        raise ValueError('absent_trial_not_pre_receive')
    projection = diagnostic.parse_inner(original, raw)
    busy = diagnostic.one_literal(raw, 'OBSERVATION_LOCK_BUSY_COUNT')
    if type(busy) is not int or not 0 <= busy <= 500:
        raise ValueError('observation_busy_count_unknown')
    return remote, component, smoke, projection, missing, busy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    mode = 'device' if args.check_device else 'source'
    out = BASE / 'results' / ('receive-advertise-smoke-v3-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, helpers, program = {}, None, None
    report = dict(schema='p011-receive-advertise-smoke-v3', mode=mode, passed=False,
        source_checked=False, source_preserved=False, diagnostic_complete=False, device_invoked=False,
        host_exit='NOT_RUN', remote_exit='NOT_RUN', host_error=None, device_outcome='NOT_RUN',
        old_v1_runtime_modified=False, old_runtime_graph_modified=False, old_tests_replayed=0,
        runtime_v2_selected=True, runtime_v2_bytes=RUNTIME_V2[1], runtime_v2_sha256=RUNTIME_V2[2],
        old_graph_ast_replayed=False, source_runtime_graph_executed=False,
        automatic_receive_action_requested=args.check_device, http_action_requested=False,
        ui_requested=False, stock_ui_taken_over=False, guardian_requested=False,
        consent_accept_requested=False, scan_requested=False, send_requested=False,
        phone_tested=False, file_transfer_verified=False, full_network_restore_verified=False,
        original_activity_seconds=60, original_cleanup_seconds=60, observation_max_seconds=15,
        remote_alarm_seconds=240, host_timeout_seconds=250)
    try:
        raw = (BASE / DIAGNOSTIC[0]).read_bytes()
        if len(raw) != DIAGNOSTIC[1] or digest(raw) != DIAGNOSTIC[2]:
            raise ValueError('diagnostic_pin')
        diagnostic = types.ModuleType('fixed_startup_diagnostic_v2_definitions')
        diagnostic.__file__ = str(BASE / DIAGNOSTIC[0])
        exec(compile(raw, diagnostic.__file__, 'exec'), diagnostic.__dict__)
        original, original_raw = diagnostic.load_definition(diagnostic.ORIGINAL, 'fixed_interactive_definitions')
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
        retain(DIAGNOSTIC[0], raw); retain(diagnostic.ORIGINAL[0], original_raw)
        retain(diagnostic.V1_HOST[0], v1_raw); retain(original.CHECKER[0], bootstrap_raw)
        for pin in (original.MANIFEST, original.PRIVATE_MANIFEST, original.RUNNER, original.TRANSPORT,
                    v1.SMOKE, diagnostic.INNER, RUNTIME_V2):
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
        # Parse only this NEW host and the NEW composition, not old graph/tests.
        ast.parse(inputs[SELF].decode('ascii'))
        ast.parse(inputs[RUNTIME_V2[0]].decode('ascii'), feature_version=(3, 5))
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
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(240);'
                'exec(sys.stdin.buffer.read(' + str(len(program)) + '))" p011-receive-advertise-smoke-v3; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True
            raw = adb.run('advertise-smoke', ['shell', command], timeout=250, input_data=program)
            report['remote_exit'] = v1.exit_marker(raw)
            remote, component, smoke, projection, missing, busy = parse_observation(
                original, v1, diagnostic, helpers, raw)
            report.update(diagnostic_complete=True, smoke_complete=smoke['complete'], reason=smoke['reason'],
                trial_absent_startup_branch=missing, original_component_complete=component['complete'],
                inner_error_projection=projection, original_inner_error_available=projection['reason'] == 'observed',
                observation_lock_busy_count=busy,
                device_outcome='FAIL_STARTUP_BEFORE_RECEIVE' if missing else
                    'ADVERTISING_SMOKE_PASS' if smoke['complete'] else 'ADVERTISING_SMOKE_FAIL')
            for key, value in smoke['flags'].items():
                report[key] = value
            if smoke['terminal'] is not None:
                for key, value in smoke['terminal'].items():
                    report['terminal_' + key] = value
            for key, value in component.items():
                report['component_' + key] = value
            write_new(out / 'private-observation.json', (json.dumps(dict(smoke=smoke, inner=projection),
                sort_keys=True, indent=2) + '\n').encode('ascii'))
    except Exception as error:
        report['host_error'] = type(error).__name__
        write_new(private / 'host-error.txt', traceback.format_exc().encode('utf-8'))
    finally:
        prefix = private / '01-advertise-smoke'
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
         report['remote_exit'] == 0 and report.get('smoke_complete') is True))
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Isolated runtime-v2 changes observation lock-busy to retry inside the original absolute cap; '
        b'busy alone is never identity failure, advertising or success. After successful lock all original '
        b'identity/field gates remain. Frozen fixed75 and 60+60/15 are unchanged. Same-run inner error '
        b'projection and actual busy count are exported. Old v1/v2 sources are never modified. Strict Trial '
        b'None failure parser are added. No Qt/guardian/HTTP action/accept/scan/send or fake ACK. Original '
        b'closed-policy complete is preserved separately. Default PC SOURCE parses only new composition; '
        b'--check-device explicitly invokes actual one-shot advert/cancel. A pre-start failure can now be '
        b'parsed but remains remote1 and FAIL, never advertisement success. Physical closure and pending '
        b'remain original retained inventory. No phone/file/TLS or full-network PASS is claimed.\n')
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
