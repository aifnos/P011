"""Thin Receive UI-v1 graph startup preparation; default SOURCE only.

Explicit device mode prepares original fixed graph75, Boot/Owner startup and
close with original diagnostic60+60. No RF/UI/phone/HTTP request or pending
handling. This is not the UI interactive600+60 smoke or a performance test.
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
SELF = 'host/device_receive_ui_v1_startup_check.py'
CMDS = ('HOST_MTA_RECEIVE_UI_V1_STARTUP_CHECK.cmd',
        'TEST_MTA_RECEIVE_UI_V1_STARTUP.cmd')
DEFINITIONS = ('host/formal_receive_ui_v1_definitions.py', 10721,
    '9450c13671d0f2c9ff113f1b369ce4a83175aace2834585b74ff3e2f1bd33bc8')
ORIGINAL = ('host/device_receive_alias_clock_startup_v1_check.py', 11514,
    '59db4834c9508210aa0962beb8a1c23bf63dac1a08afc62bd3201ef2337bd900')
ORIGINAL_RAW = (BASE / ORIGINAL[0]).read_bytes()
if (len(ORIGINAL_RAW), hashlib.sha256(ORIGINAL_RAW).hexdigest()) != ORIGINAL[1:]:
    raise ValueError('original_startup_checker_pin')
_origin = types.ModuleType('fixed_original_receive_startup_helpers')
_origin.__file__ = str(BASE / ORIGINAL[0])
_tree = ast.parse(ORIGINAL_RAW.decode('ascii'), filename=_origin.__file__)
_names = ('digest', 'write_new', 'make_source', 'closed_policy')
_nodes = [node for node in _tree.body if isinstance(node, ast.FunctionDef) and node.name in _names]
if tuple(node.name for node in _nodes) != _names:
    raise ValueError('original_startup_helper_definitions')
_constants = {node.targets[0].id: ast.literal_eval(node.value) for node in _tree.body
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and
    isinstance(node.targets[0], ast.Name) and node.targets[0].id in ('BEFORE', 'AFTER')}
if set(_constants) != {'BEFORE', 'AFTER'} or any(type(value) is not bytes for value in _constants.values()):
    raise ValueError('original_startup_envelope_literals')
_origin.__dict__.update(_constants)
_origin.__dict__['hashlib'] = hashlib
exec(compile(ast.Module(body=_nodes, type_ignores=[]), _origin.__file__, 'exec'), _origin.__dict__)
digest, write_new = _origin.digest, _origin.write_new
make_source, closed_policy = _origin.make_source, _origin.closed_policy
if 'main' in _origin.__dict__:
    raise ValueError('old_main_forbidden')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    mode = 'device' if args.check_device else 'source'
    out = BASE / 'results' / ('receive-ui-v1-startup-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, helpers, program, original, component, trials = {}, None, None, None, None, None
    report = dict(schema='p011-receive-ui-v1-startup', mode=mode, passed=False,
        source_checked=False, source_preserved=False, device_invoked=False, host_error=None,
        host_exit='NOT_RUN', remote_exit='NOT_RUN', component=None, trial_facts=None,
        closed_policy_verified=False, production_sources_modified=False, graph_ast_replayed=False,
        old_tests_executed=False, source_runtime_graph_executed=False, envelope_literal_delta_count=1,
        policy_requested=False, ui_requested=False, phone_requested=False, rf_action_requested=False,
        ble_listen_requested=False, advertising_requested=False, wifi_action_requested=False,
        http_request_issued=False, local_http_listener_expected=True, pending_handled=False,
        original_activity_seconds=60, original_cleanup_seconds=60, remote_alarm_seconds=240,
        host_timeout_seconds=250, ui_display_exercised=False, receive_performance_verified=False,
        origin_checker_bytes=ORIGINAL[1], origin_checker_sha256=ORIGINAL[2])
    try:
        raw = (BASE / DEFINITIONS[0]).read_bytes()
        if (len(raw), digest(raw)) != DEFINITIONS[1:]: raise ValueError('definitions_pin')
        definitions = types.ModuleType('fixed_receive_ui_v1_startup_definitions')
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
        retain(ORIGINAL[0], ORIGINAL_RAW)
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
                'exec(sys.stdin.buffer.read('+str(len(program))+'))" p011-receive-ui-v1-startup; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked']=True
            output=adb.run('receive-ui-v1-startup',['shell',command],timeout=250,input_data=program)
            remote,component=helpers.parse_result(output)
            trials=definitions.parse_trial_facts(output)
            report.update(remote_exit=remote,component=component,trial_facts=trials,
                closed_policy_verified=closed_policy(helpers,component,trials))
    except Exception as error:
        report['host_error']=type(error).__name__
        write_new(private/'host-error.txt',traceback.format_exc().encode('utf-8'))
    finally:
        prefix=private/'01-receive-ui-v1-startup'
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
    readme=(b'New Receive UI-v1 fixed graph75 preparation and Boot/Owner startup/close only. Production source bytes remain frozen. '
        b'The original startup checker raw/pin is retained privately; only four pure definitions are loaded, never its main. '
        b'Thin envelope changes only '
        b'one requestedTrue literal to False; original diagnostic60+cleanup60, alarm240/host250. '
        b'Device explicitly stages fixed absent graph, Boot/Owner/startup and original close, with loopback '
        b'HTTP listener but no HTTP request, BLE listen/advert/scan, Wi-Fi action, UI, phone, accept/send/file '
        b'or pending handling. Original complete/closed-policy gates/pending/baseline/FD predicates remain. '
        b'Both real Trial facts must be requestedFalse/unavailable/unclaimed/claim0/noSession. '
        b'No UI display, interactive600+60 receive Trial, handoff or performance PASS is claimed. Default SOURCE '
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
