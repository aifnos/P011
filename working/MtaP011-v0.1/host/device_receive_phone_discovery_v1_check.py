"""One real phone discovery opportunity, PC SOURCE unless --check-device.

Uses original receive-interactive-v1 600+60 once. Actual advertising must occur
within 15 seconds, then one 45-second opportunity. No accept/send/Qt. Only a live
whitelisted READY line from actual raw stdout is forwarded to the operator.
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
SELF = 'host/device_receive_phone_discovery_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_PHONE_DISCOVERY_V1_CHECK.cmd', 'TEST_MTA_RECEIVE_PHONE_DISCOVERY_V1.cmd')
DIAGNOSTIC = ('host/device_receive_advertise_smoke_v2_diagnostic.py', 19645,
              'c33a0e73569ddac453230e0ba509955a4b08a84742633b021c433b8dc77d6201')
RUNTIME_V2 = ('candidate/receive-phone-discovery-v1/runtime/phone_discovery_session.py', 16332,
              '66554a39a63f95bad6b683f2121dd3a58417ab2b63168dd2a1db4a72eda0b34e')


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
        "print('OBSERVATION_LOCK_BUSY_COUNT='+repr(smoke._OBSERVATION_BUSY_COUNT))\n"
        "print('PHONE_WINDOW_RESULT='+repr(smoke._PHONE_WINDOW))\n")
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
    if type(busy) is not int or not 0 <= busy <= 1000:
        raise ValueError('observation_busy_count_unknown')
    window = diagnostic.one_literal(raw, 'PHONE_WINDOW_RESULT')
    ready_rows = re.findall(r'^PHONE_DISCOVERY_READY=(.*)$',
        raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n'), re.M)
    if window is None:
        if smoke['observations'] or smoke['complete'] or ready_rows:
            raise ValueError('phone_window_absent_after_observation')
    else:
        if (type(window) is not dict or set(window) !=
                {'ready', 'completed', 'ready_elapsed', 'opportunity_seconds', 'elapsed'} or
                type(window['ready']) is not bool or type(window['completed']) is not bool or
                type(window['opportunity_seconds']) is not float or window['opportunity_seconds'] != 45.0):
            raise ValueError('phone_window_fields')
        if window['ready']:
            if (type(window['ready_elapsed']) is not float or not 0 <= window['ready_elapsed'] <= 15 or
                    type(window['elapsed']) is not float or not 0 <= window['elapsed'] <= 60 or
                    len(ready_rows) != 1 or parse_ready(ready_rows[0].encode('ascii')) != READY_VALUE or
                    not any(row['advertising'] for row in smoke['observations'])):
                raise ValueError('phone_window_ready_unknown')
        elif window['completed'] or window['ready_elapsed'] is not None or window['elapsed'] is not None or ready_rows:
            raise ValueError('phone_window_unready_unknown')
        if window['completed'] and (not window['ready'] or window['elapsed'] < 45.0):
            raise ValueError('phone_window_early_completion')
    if smoke['complete'] and (window is None or window['completed'] is not True):
        raise ValueError('phone_window_not_completed')
    return remote, component, smoke, projection, missing, busy, window


READY_VALUE = dict(ready=True, opportunity_seconds=45.0, accept_allowed=False, send_allowed=False)


def parse_ready(raw):
    value = ast.literal_eval(raw.decode('ascii'))
    if (type(value) is not dict or set(value) != set(READY_VALUE) or
            any(type(value[key]) is not bool or value[key] is not READY_VALUE[key]
                for key in ('ready', 'accept_allowed', 'send_allowed')) or
            type(value['opportunity_seconds']) is not float or value['opportunity_seconds'] != 45.0):
        raise ValueError('live_ready_fields')
    return value


def collect_ready_pipe(pipe, path, inspect_ready, ready, errors, process):
    pending = b''
    dropping = False
    count = 0
    try:
        with path.open('xb') as handle:
            while True:
                block = pipe.read1(4096)
                if not block:
                    break
                handle.write(block)
                handle.flush()
                count += len(block)
                if count > 16777216:
                    raise ValueError('live_raw_budget')
                if not inspect_ready:
                    continue
                for part in block.splitlines(True):
                    pending += part
                    if pending.endswith(b'\n'):
                        line = pending.rstrip(b'\r\n')
                        if not dropping and line.startswith(b'PHONE_DISCOVERY_READY='):
                            value = parse_ready(line[len(b'PHONE_DISCOVERY_READY='):])
                            if ready:
                                raise ValueError('duplicate_live_ready')
                            ready.append(value)
                            print('PHONE_DISCOVERY_READY=' + repr(value), flush=True)
                        pending, dropping = b'', False
                    elif len(pending) > 4096:
                        pending, dropping = b'', True
            if pending and not dropping and pending.startswith(b'PHONE_DISCOVERY_READY='):
                raise ValueError('unterminated_live_ready')
    except BaseException as error:
        errors.append(error)
        try:
            process.kill()
        except OSError:
            pass
    finally:
        pipe.close()

def dispatch_live(transport, adb, private, program, command, timeout):
    """Retain exact pipes; forward only the anchored typed native READY line."""
    prefix = private / '01-phone-discovery'
    errors, ready = [], []
    process = subprocess.Popen([str(transport.ADB), '-t', adb.transport, 'shell', command],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = threading.Event()
    done = threading.Event()
    def watchdog():
        if not done.wait(timeout):
            timed_out.set()
            try:
                process.kill()
            except OSError:
                pass
    workers = [threading.Thread(target=collect_ready_pipe, args=(process.stdout, Path(str(prefix) + '.stdout.raw'), True, ready, errors, process)),
               threading.Thread(target=collect_ready_pipe, args=(process.stderr, Path(str(prefix) + '.stderr.raw'), False, ready, errors, process))]
    for worker in workers:
        worker.start()
    guard = threading.Thread(target=watchdog)
    guard.start()
    try:
        process.stdin.write(program)
        process.stdin.close()
        code = process.wait(timeout=timeout + 1)
    finally:
        done.set()
        guard.join(1)
        for worker in workers:
            worker.join(2)
        write_new(Path(str(prefix) + '.host-exit'),
            (('TIMEOUT' if timed_out.is_set() else str(process.poll())) + '\n').encode('ascii'))
    if any(worker.is_alive() for worker in workers):
        raise ValueError('live_pipe_reader_pending')
    if timed_out.is_set():
        raise RuntimeError('live_host_timeout')
    if errors:
        raise errors[0]
    if code != 0:
        raise RuntimeError('live_adb_host_exit')
    return Path(str(prefix) + '.stdout.raw').read_bytes(), ready

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    mode = 'device' if args.check_device else 'source'
    out = BASE / 'results' / ('receive-phone-discovery-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, helpers, program = {}, None, None
    report = dict(schema='p011-receive-phone-discovery-v1', mode=mode, passed=False,
        source_checked=False, source_preserved=False, diagnostic_complete=False, device_invoked=False,
        host_exit='NOT_RUN', remote_exit='NOT_RUN', host_error=None, device_outcome='NOT_RUN',
        old_v1_runtime_modified=False, old_runtime_graph_modified=False, old_tests_replayed=0,
        runtime_v2_selected=True, runtime_v2_bytes=RUNTIME_V2[1], runtime_v2_sha256=RUNTIME_V2[2],
        old_graph_ast_replayed=False, source_runtime_graph_executed=False,
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
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(780);'
                'exec(sys.stdin.buffer.read(' + str(len(program)) + '))" p011-receive-phone-discovery-v1; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True
            print('PHONE_DISCOVERY_LOG_DIR=' + str(out), flush=True)
            raw, live_ready = dispatch_live(transport, adb, private, program, command, 790)
            report['live_ready_forwarded'] = len(live_ready) == 1
            report['remote_exit'] = v1.exit_marker(raw)
            remote, component, smoke, projection, missing, busy, window = parse_observation(
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
         report['remote_exit'] == 0 and report.get('smoke_complete') is True))
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Original fixed75 remains unchanged. Existing receive-interactive-v1 constructor selects '
        b'600+60 once, without renewal. Fifteen seconds to actual advertising; only then one fixed '
        b'45-second phone discovery opportunity. Actual native/identity gates retained; busy retries '
        b'are not evidence. A whitelist anchored typed READY line is forwarded live from raw stdout, '
        b'not from elapsed time. Original stdout/stderr/host/remote exits retained privately. '
        b'Peer handoff cancels through original finally and used-network cleanup; no accept/send/Qt. '
        b'Window completion with closure is NOT phone discovery or transfer acceptance. '
        b'Default PC SOURCE parses only new host/runtime/composition; no old suite or graph execution.\n')
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
