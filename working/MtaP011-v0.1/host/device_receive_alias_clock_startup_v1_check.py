"""Thin no-admission alias-clock startup diagnostic; default SOURCE only.

Explicit device mode stages the fixed new graph, runs original Boot/Owner
startup and close; no phone/RF/UI/HTTP request or record handling. This does
not exercise the Publication alias callback or prove its performance.
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
SELF = 'host/device_receive_alias_clock_startup_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_ALIAS_CLOCK_STARTUP_V1_CHECK.cmd',
        'TEST_MTA_RECEIVE_ALIAS_CLOCK_STARTUP_V1.cmd')
DEFINITIONS = ('host/formal_receive_alias_clock_v1_definitions.py', 19468,
    '7bd0155ae2ddcb0892bf53e0429bd323b02046b8c5a365531fb929bce7e9e6e1')
BEFORE = b'component=session.run_fixed(artifacts,False,receive_trial_requested=True)'
AFTER = b'component=session.run_fixed(artifacts,False,receive_trial_requested=False)'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw): raise OSError('short_write')


def make_source(definitions, helpers, inputs, payload):
    original = definitions.make_source(helpers, inputs, payload, False)
    tail = definitions.TARGET_SERVICE.encode('ascii')
    if not original.endswith(tail) or tail.count(BEFORE) != 1 or original.count(BEFORE) != 1:
        raise ValueError('startup_original_envelope')
    selected = original[:-len(tail)] + tail.replace(BEFORE, AFTER)
    if selected.count(AFTER) != 1 or selected.replace(AFTER, BEFORE) != original:
        raise ValueError('startup_envelope_delta')
    if len(selected) > 2097152 or any(len(row) > 256 for row in selected.splitlines()):
        raise ValueError('target_source_budget')
    return original, selected


def closed_policy(helpers, component, trials):
    required = helpers.COMMON + tuple(k for k in helpers.SERVICE if k != 'http_verified') + ('complete',)
    return (all(component[k] is True for k in required) and component['reason'] == 'complete' and
        component['resource_pending'] is False and component['staging_pending'] is False and
        component['interactive_window_requested'] is False and component['http_verified'] is False and
        component['http_request_count'] == 0 and component['client_socket_count'] == 0 and
        component['runner_opened_fd_count'] == component['runner_closed_fd_count'] and
        all(t['requested'] is False and t['available'] is False and t['claimed'] is False and
            t['claim_count'] == 0 and t['session_attached'] is False and
            t['restoration_verified'] is False and t['phone_verified'] is False for t in trials.values()) and
        trials['start']['reason'] == 'not_requested' and trials['end']['revoked'] is True and
        trials['end']['reason'] == 'owner_closed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    mode = 'device' if args.check_device else 'source'
    out = BASE / 'results' / ('receive-alias-clock-startup-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, helpers, program, original, component, trials = {}, None, None, None, None, None
    report = dict(schema='p011-receive-alias-clock-startup-v1', mode=mode, passed=False,
        source_checked=False, source_preserved=False, device_invoked=False, host_error=None,
        host_exit='NOT_RUN', remote_exit='NOT_RUN', component=None, trial_facts=None,
        closed_policy_verified=False, production_sources_modified=False, graph_ast_replayed=False,
        old_tests_executed=False, source_runtime_graph_executed=False, envelope_literal_delta_count=1,
        policy_requested=False, ui_requested=False, phone_requested=False, rf_action_requested=False,
        ble_listen_requested=False, advertising_requested=False, wifi_action_requested=False,
        http_request_issued=False, local_http_listener_expected=True, pending_handled=False,
        original_activity_seconds=60, original_cleanup_seconds=60, remote_alarm_seconds=240,
        host_timeout_seconds=250, alias_callback_exercised=False, alias_performance_verified=False)
    try:
        raw = (BASE / DEFINITIONS[0]).read_bytes()
        if (len(raw), digest(raw)) != DEFINITIONS[1:]: raise ValueError('definitions_pin')
        definitions = types.ModuleType('fixed_alias_clock_startup_definitions')
        definitions.__file__ = str(BASE / DEFINITIONS[0])
        exec(compile(raw, definitions.__file__, 'exec'), definitions.__dict__)
        helpers, bootstrap = definitions.load_checker()
        def retain(path, value):
            if path in inputs:
                if inputs[path] != value: raise ValueError('shared_input_changed')
                return
            inputs[path] = value
            saved = out / 'private-inputs' / path; saved.parent.mkdir(parents=True, exist_ok=True)
            write_new(saved, value)
        retain(DEFINITIONS[0], raw); retain(definitions.CHECKER[0], bootstrap)
        realm = definitions
        while type(realm) is types.ModuleType and hasattr(realm, 'ORIGINAL'):
            retain(realm.ORIGINAL[0], realm.ORIGINAL_RAW)
            for attr in ('ORIGINAL_MANIFEST', 'OLD_PRIVATE_MANIFEST'):
                pin = getattr(realm, attr, None)
                if pin is not None: retain(pin[0], helpers.read_fixed(pin[0], pin[1:]))
            realm = getattr(realm, '_old', None)
        for pin in (definitions.MANIFEST, definitions.PRIVATE_MANIFEST, definitions.RUNNER, definitions.TRANSPORT):
            retain(pin[0], helpers.read_fixed(pin[0], pin[1:]))
        payload = (definitions.manifest_rows(inputs[definitions.MANIFEST[0]]) + definitions.HELPERS +
            definitions.manifest_rows(inputs[definitions.PRIVATE_MANIFEST[0]], private=True) +
            (definitions.WPA, definitions.MONITOR))
        if len(payload) != 75 or len({r[0] for r in payload}) != 75 or sum(r[2] for r in payload) > 4194304:
            raise ValueError('payload_budget')
        for name, path, size, sha in payload: retain(path, helpers.read_fixed(path, (size, sha)))
        for path in (SELF,) + CMDS: retain(path, helpers.read_fixed(path))
        ast.parse(inputs[SELF].decode('ascii'))
        original, program = make_source(definitions, helpers, inputs, payload)
        ast.parse(program.decode('ascii'), feature_version=(3, 5))
        write_new(out / 'private-original-service-target.py', original)
        write_new(out / 'private-startup-target.py', program)
        write_new(out / 'private-inputs.json', (json.dumps({p: dict(bytes=len(b),sha256=digest(b))
            for p,b in inputs.items()},sort_keys=True,indent=2)+'\n').encode('ascii'))
        report.update(source_checked=True,source_count=len(inputs),payload_role_count=75,
            target_bytes=len(program),target_sha256=digest(program),
            target_max_line_bytes=max(map(len,program.splitlines())))
        if args.check_device:
            transport=helpers.load_transport(inputs[definitions.TRANSPORT[0]])
            adb=transport.Adb(private)
            command=('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(240);'
                'exec(sys.stdin.buffer.read('+str(len(program))+'))" p011-alias-clock-startup-v1; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked']=True
            output=adb.run('alias-clock-startup',['shell',command],timeout=250,input_data=program)
            remote,component=helpers.parse_result(output)
            trials=definitions.parse_trial_facts(output)
            report.update(remote_exit=remote,component=component,trial_facts=trials,
                closed_policy_verified=closed_policy(helpers,component,trials))
    except Exception as error:
        report['host_error']=type(error).__name__
        write_new(private/'host-error.txt',traceback.format_exc().encode('utf-8'))
    finally:
        prefix=private/'01-alias-clock-startup'
        for tag in ('stdout','stderr'):
            path=Path(str(prefix)+'.'+tag+'.raw')
            if path.exists():
                value=path.read_bytes();report[tag+'_bytes']=len(value);report[tag+'_sha256']=digest(value)
                if tag=='stdout':
                    text=value.decode('utf-8','replace').replace('\r\r\n','\n').replace('\r\n','\n')
                    exits=re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$',text,re.M)
                    report['remote_exit']=int(exits[0]) if len(exits)==1 else 'UNKNOWN'
        path=Path(str(prefix)+'.host-exit')
        if path.exists():
            text=path.read_text(encoding='ascii').strip()
            report['host_exit']=int(text) if re.fullmatch(r'-?\d+',text) else 'TIMEOUT'
        write_new(private/'remote-exit',(str(report['remote_exit'])+'\n').encode('ascii'))
        try:
            report['source_preserved']=bool(inputs) and helpers is not None and program is not None and all(
                helpers.read_fixed(p)==b and (out/'private-inputs'/p).read_bytes()==b for p,b in inputs.items()) and (
                out/'private-startup-target.py').read_bytes()==program and (
                out/'private-original-service-target.py').read_bytes()==original
        except Exception: report['source_preserved']=False
    report['passed']=(report['source_checked'] and report['source_preserved'] and report['host_error'] is None and
        (not args.check_device or report['host_exit']==0 and report.get('stderr_bytes')==0 and
         report['remote_exit']==0 and report['closed_policy_verified'] is True))
    public=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode('ascii')
    readme=(b'Original alias-clock graph75 and six-source closure unchanged. Thin envelope changes only '
        b'one requestedTrue literal to False; original diagnostic60+cleanup60, alarm240/host250. '
        b'Device explicitly stages fixed absent graph, Boot/Owner/startup and original close, with loopback '
        b'HTTP listener but no HTTP request, BLE listen/advert/scan, Wi-Fi action, UI, phone, accept/send/file '
        b'or pending handling. Original complete/closed-policy gates/pending/baseline/FD predicates remain. '
        b'Both real Trial facts must be requestedFalse/unavailable/unclaimed/claim0/noSession. '
        b'No alias callback is exercised and no handoff or performance PASS is claimed. Default SOURCE '
        b'checks only new driver/envelope syntax, exact single delta, payload pins and budgets.\n')
    write_new(out/'result.json',public);write_new(out/'README.txt',readme)
    bundle=out/'public-result.zip'
    with zipfile.ZipFile(bundle,'x',zipfile.ZIP_DEFLATED) as z:
        z.writestr('result.json',public);z.writestr('README.txt',readme)
    with zipfile.ZipFile(bundle) as z:
        if z.namelist()!=['result.json','README.txt'] or z.read('result.json')!=public or z.read('README.txt')!=readme:
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'],mode=mode,result_dir=str(out),
        public_result_zip=str(bundle),zip_sha256=digest(bundle.read_bytes())),sort_keys=True))
    return 0 if report['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
