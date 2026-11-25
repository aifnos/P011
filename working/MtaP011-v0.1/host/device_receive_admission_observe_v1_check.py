"""Thin observation of the unchanged receive-interactive service path.

Default SOURCE only; explicit --check-device runs its original service runner,
never UI/smoke/HTTP actions/discover/scan/receive. It may verify/stage the fixed
volatile assets and briefly listen on localhost as the original Owner does.
No ready/refused fact modifies admission or overrides runner complete/exit.
Raw original TRIAL_START/END, component, stdout/stderr and exits are preserved.
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
ORIGINAL = ('host/device_receive_interactive_v1_check.py', 51764,
    '85744bf1c282b55b997911222f9dfb83b5f3ffdb9badc956017ef551521c58ca')
SELF = 'host/device_receive_admission_observe_v1_check.py'
CMD = 'CHECK_MTA_RECEIVE_ADMISSION_OBSERVE_V1.cmd'
REFUSALS = ('pending_exists', 'pending_symlink', 'client_root_missing', 'client_history',
            'radio_unavailable', 'radio_busy')
NO_REQUEST_COUNTS = ('http_request_count', 'client_socket_count')


def digest(raw): return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw): raise OSError('short_write')


def exit_marker(raw):
    text = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    values = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', text, re.M)
    return int(values[0]) if len(values) == 1 else 'UNKNOWN'


def classify(checker, component, facts, remote):
    """Original observations only, not an RF/Session/restore producer."""
    if type(component) is not dict or type(facts) is not dict or remote not in (0, 1):
        return 'unknown', False
    start, end = facts['start'], facts['end']
    # Keep the original runner outcome. Ready need not satisfy its intentionally
    # closed-policy gates_remained_closed/complete predicate; those raw False
    # values and remote1 remain visible, not rewritten into success.
    if remote != (0 if component['complete'] else 1): return 'unknown', False
    service = tuple(key for key in checker.SERVICE if key not in ('http_verified', 'gates_remained_closed'))
    closed = (all(component[key] is True for key in checker.COMMON + service) and
        component['resource_pending'] is False and component['staging_pending'] is False and
        component['http_verified'] is False and component['interactive_window_requested'] is False and
        all(component[key] == 0 for key in NO_REQUEST_COUNTS) and
        start['requested'] is True and end['requested'] is True and
        all(value['claimed'] is False and value['claim_count'] == 0 and value['session_attached'] is False and
            value['restoration_verified'] is False and value['phone_verified'] is False for value in (start, end)) and
        start['revoked'] is False and start['expired'] is False and
        end['available'] is False and end['revoked'] is True and end['reason'] == 'owner_closed')
    if not closed: return 'unknown', False
    qualified = all(start[key] is True for key in
        ('startup_verified', 'probe_verified', 'radio_known', 'network_spec_verified'))
    if qualified and start['available'] is True and start['barrier_clear'] is True and start['reason'] == 'ready':
        return 'observed-ready', True
    if qualified and start['available'] is False and start['reason'] in REFUSALS:
        return 'observed-refused', True
    return 'unknown', True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    mode = 'service' if args.check_device else 'source'
    out = BASE / 'results' / ('receive-admission-observe-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, component, facts, program, helpers = {}, None, None, None, None
    report = dict(schema='p011-receive-admission-service-observe-v1', mode=mode, passed=False,
        source_checked=False, source_preserved=False, source_count=0, payload_role_count=0,
        old_graph_ast_replayed=False, old_tests_replayed=0, old_checker_main_called=False,
        source_runtime_graph_executed=False, device_invoked=False, classification='SOURCE_ONLY',
        observation_received=False, closed_baseline_verified=False, observed_receive_ready=False,
        original_runner_complete=None, original_component_reason=None,
        host_exit='NOT_RUN', remote_exit='NOT_RUN', remote_status_known=False, host_error=None,
        receive_trial_policy_requested=args.check_device, automatic_receive_action_issued=False,
        http_action_requested=False, http_smoke_replayed=False, ui_requested=False,
        mta_scan_requested=False, mta_receive_requested=False, mta_send_requested=False,
        rf_requested=False, receive_admission_granted=False, phone_tested=False,
        restoration_verified=False, whole_system_zero_rf_claimed=False,
        old_records_handled=False, vendor_binary_replaced=False,
        fixed_volatile_assets_may_be_staged=args.check_device,
        original_activity_seconds=60, original_cleanup_seconds=60,
        remote_alarm_seconds=240, host_timeout_seconds=250,
        source_scope='unchanged_fixed_pins_and_one_service_envelope_only')
    try:
        path = BASE / ORIGINAL[0]
        raw = path.read_bytes()
        if len(raw) != ORIGINAL[1] or digest(raw) != ORIGINAL[2]: raise ValueError('original_pin')
        original = types.ModuleType('fixed_receive_interactive_host_definitions')
        original.__file__ = str(path)
        exec(compile(raw, str(path), 'exec'), original.__dict__)
        # Definitions only. Neither old checker main nor check_source_graph,
        # UI packing, old AST tests or HTTP smoke is invoked in this wrapper.
        helpers, bootstrap_raw = original.load_checker()
        def retain(path, raw):
            if path in inputs:
                if inputs[path] != raw: raise ValueError('shared_input_changed')
                return
            inputs[path] = raw
            saved = out / 'private-inputs' / path; saved.parent.mkdir(parents=True, exist_ok=True)
            write_new(saved, raw)
        retain(ORIGINAL[0], raw); retain(original.CHECKER[0], bootstrap_raw)
        for pin in (original.MANIFEST, original.PRIVATE_MANIFEST, original.RUNNER, original.TRANSPORT):
            retain(pin[0], helpers.read_fixed(pin[0], pin[1:]))
        rows = original.manifest_rows(inputs[original.MANIFEST[0]])
        private_rows = original.manifest_rows(inputs[original.PRIVATE_MANIFEST[0]], private=True)
        payload = rows + original.HELPERS + private_rows + (original.WPA, original.MONITOR)
        if len(payload) != 75 or len({row[0] for row in payload}) != 75 or sum(row[2] for row in payload) > 4 * 1024 * 1024:
            raise ValueError('payload_budget')
        for name, path, size, sha in payload: retain(path, helpers.read_fixed(path, (size, sha)))
        for path in (SELF, CMD): retain(path, helpers.read_fixed(path))
        write_new(out / 'private-inputs.json', (json.dumps({path: dict(bytes=len(raw), sha256=digest(raw))
            for path, raw in inputs.items()}, sort_keys=True, indent=2) + '\n').encode('ascii'))
        program = original.make_source(helpers, inputs, payload, False)
        # Only the new selected envelope gets a syntax check. All original
        # 75 runtime payload definitions are pinned bytes, not HOST execution.
        ast.parse(program.decode('ascii'), feature_version=(3, 5))
        write_new(out / 'private-service-target.py', program)
        report.update(source_checked=True, source_count=len(inputs), payload_role_count=len(payload),
            target_bytes=len(program), target_sha256=digest(program),
            target_max_line_bytes=max(map(len, program.splitlines())))
        if args.check_device:
            transport = helpers.load_transport(inputs[original.TRANSPORT[0]])
            adb = transport.Adb(private)
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(240);'
                'exec(sys.stdin.buffer.read(' + str(len(program)) + '))" p011-receive-admission-observe-v1; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True; report['classification'] = 'unknown'
            raw = adb.run('service-observe', ['shell', command], timeout=250, input_data=program)
            # Preserve actual remote exit before any result parser may reject.
            report['remote_exit'] = exit_marker(raw)
            remote, component = helpers.parse_result(raw)
            facts = original.parse_trial_facts(raw)
            report.update(observation_received=True, original_runner_complete=component['complete'],
                original_component_reason=component['reason'])
            classification, closed = classify(helpers, component, facts, remote)
            report.update(classification=classification, closed_baseline_verified=closed,
                observed_receive_ready=classification == 'observed-ready')
            # Exact producer fields are preserved separately, never replaced
            # by classification or a new admission/cleanup receipt.
            for key, value in component.items(): report['component_' + key] = value
            for tag, value in facts.items():
                for key, item in value.items(): report['trial_' + tag + '_' + key] = item
            write_new(out / 'private-observation.json', (json.dumps(dict(component=component, trials=facts),
                sort_keys=True, indent=2) + '\n').encode('ascii'))
    except Exception as error:
        report['host_error'] = type(error).__name__
        write_new(private / 'host-error.txt', traceback.format_exc().encode('utf-8'))
    finally:
        prefix = private / '01-service-observe'
        for tag in ('stdout', 'stderr'):
            path = Path(str(prefix) + '.' + tag + '.raw')
            if path.exists():
                raw = path.read_bytes(); report[tag + '_bytes'] = len(raw); report[tag + '_sha256'] = digest(raw)
                if tag == 'stdout': report['remote_exit'] = exit_marker(raw)
        path = Path(str(prefix) + '.host-exit')
        if path.exists():
            value = path.read_text(encoding='ascii').strip()
            report['host_exit'] = int(value) if re.fullmatch(r'-?\d+', value) else 'TIMEOUT'
        report['remote_status_known'] = type(report['remote_exit']) is int
        write_new(private / 'remote-exit', (str(report['remote_exit']) + '\n').encode('ascii'))
        try:
            report['source_preserved'] = bool(inputs) and helpers is not None and all(
                helpers.read_fixed(path) == raw and (out / 'private-inputs' / path).read_bytes() == raw
                for path, raw in inputs.items()) and program is not None and (
                out / 'private-service-target.py').read_bytes() == program
        except Exception: report['source_preserved'] = False
    source_ok = report['source_checked'] and report['source_preserved'] and report['host_error'] is None
    report['passed'] = source_ok and (not args.check_device or
        report['host_exit'] == 0 and report.get('stderr_bytes') == 0 and report['remote_exit'] in (0, 1) and
        report['observation_received'] and report['closed_baseline_verified'] and
        report['classification'] in ('observed-ready', 'observed-refused'))
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'New thin service observation; unchanged receive-interactive-v1 fixed runner/75-role payload. '
        b'Default SOURCE byte-pins manifests and inputs and parses one service envelope only. No old AST/model '
        b'graph, checker main, HTTP smoke or tests are replayed. Explicit check-device uses the original '
        b'60-second diagnostic constructor and original cleanup60, remote240/host250 unchanged. It may stage '
        b'only its fixed volatile assets; original Owner binds directories, pure receive Factory, capability '
        b'helpers, readonly startup/barrier/trial and localhost Server, then immediately closes via the original '
        b'runner finally. No UI, client HTTP requests, action/scan/discover/send/receive or credentials issuance. '
        b'Observations are classified observed-ready/refused/unknown using actual TRIAL_START/END and original '
        b'closure/baseline/no-claim inventories. Original complete, gates_remained_closed and remote0/1 are never '
        b'changed. In particular ready with completeFalse/remote1 is not forged into old closed-policy PASS. '
        b'PASS means this bounded observation is classified and original resources/baseline are verified; '
        b'it is not admission, Native/RF/receive/phone/restoration proof or whole-system exclusion. Unknown '
        b'producer/results/cleanup refuse PASS. Raw traces/streams and all source bytes remain private.\n')
    write_new(out / 'result.json', public); write_new(out / 'README.txt', readme)
    bundle_path = out / 'public-result.zip'
    with zipfile.ZipFile(bundle_path, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public); bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(bundle_path) as bundle:
        if bundle.namelist() != ['result.json', 'README.txt'] or bundle.read('result.json') != public or bundle.read('README.txt') != readme:
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], mode=mode, classification=report['classification'],
        result_dir=str(out), public_result_zip=str(bundle_path), zip_sha256=digest(bundle_path.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
