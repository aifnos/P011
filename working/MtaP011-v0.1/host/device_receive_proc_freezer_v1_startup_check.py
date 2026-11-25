"""Fixed durable runtime75 preparation and original closed startup diagnostic.

Default SOURCE only. Explicit --check-device stages absent exact core roles,
runs original diagnostic60+cleanup60 startup-close, and retains closed policy.
No archived main, old graph verifier, suite, UI, RF or phone action is called.
"""
import argparse
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys
import traceback
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_proc_freezer_v1_startup_check.py'
CMDS = ('HOST_MTA_RECEIVE_PROC_FREEZER_V1_STARTUP_CHECK.cmd',
        'TEST_MTA_RECEIVE_PROC_FREEZER_V1_STARTUP.cmd')
DONOR = ('host/device_receive_alias_clock_startup_v1_check.py', 11514,
         '59db4834c9508210aa0962beb8a1c23bf63dac1a08afc62bd3201ef2337bd900')
IO_DONOR = ('host/device_receive_startup_readonly_v4_check.py', 27003,
            '4ed9c5eb9403f81d967cce91bf21d71e2230d82e49e7d8dfb1d178a353311cbf')
DEFINITIONS = ('host/formal_receive_proc_freezer_v1_definitions.py', 114824, '3eb522f95f199a1efea2c2d1505a76ab6677f7f1f419e54d64d5a0866cafc21a')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
ROOT_NAME = 'p011-mta-rx-freezer-v1'
PAYLOAD_BYTES = 4191766
READ_ME = (b'Fixed durable runtime75 preparation and original closed startup diagnostic only.\n'
           b'Default SOURCE; explicit device mode may exclusively stage absent exact core roles,\n'
           b'then run original diagnostic60+cleanup60, Startup10, alarm240/host250 and closed policy.\n'
           b'Actual flat208 provenance and new 8 mechanical closures; old main/verifiers/tests/builders not called.\n'
           b'Actual75/4191766 retains original4MiB cap; FC9/113690 retains separate131072 cap.\n'
           b'FC sources are retained but no FileCenter companion or UI is created.\n'
           b'Original carrier changes exactly one receive_trial_requested=True literal to False.\n'
           b'Loopback Owner HTTP listener is expected, but no HTTP request, credential pair,\n'
           b'BLE listen/advert/scan, Wi-Fi action, phone, transfer or old pending handling is requested.\n'
           b'Existing complete exact state/GO roots are accepted; partial/conflicting trees stay untouched.\n'
           b'Raw errors, stdout/stderr, exits, exact inputs and original/selected carrier remain private.\n'
           b'FAIL and missing/None Trial parsing stay FAIL; component facts never replace original closed gates.\n'
           b'Private ZIP CRC/member readback precedes public result commit.\n'
           b'SOURCE is not P011 runtime; startup-close is not navigation, radio restoration or phone acceptance.\n')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_fixed(name, pin=None):
    if (type(name) is not str or not name or '\\' in name or
            PurePosixPath(name).is_absolute() or re.fullmatch(r'[A-Za-z0-9_./-]+', name) is None or
            any(part in ('', '.', '..') for part in name.split('/'))):
        raise ValueError('fixed_path')
    path = BASE
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or
                getattr(value, 'st_file_attributes', 0) & 0x400): raise ValueError('fixed_ancestor')
    for index, part in enumerate(name.split('/')):
        path = path / part; value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise ValueError('fixed_link')
        if index < len(name.split('/')) - 1 and not stat.S_ISDIR(value.st_mode):
            raise ValueError('fixed_ancestor')
    if not stat.S_ISREG(value.st_mode) or not 0 < value.st_size <= 2 * 1024 * 1024:
        raise ValueError('fixed_file')
    before = metadata(value)
    with path.open('rb') as handle:
        opened = metadata(os.fstat(handle.fileno()))
        if os.name == 'nt':
            equal = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                     opened[3:6] == before[3:6])
        else: equal = opened == before
        if not equal: raise ValueError('fixed_identity')
        raw = handle.read(2 * 1024 * 1024 + 1)
        if metadata(os.fstat(handle.fileno())) != opened: raise ValueError('fixed_changed')
    if metadata(path.lstat()) != before or len(raw) != before[4]: raise ValueError('fixed_changed')
    if pin is not None and (len(raw), digest(raw)) != pin: raise ValueError('fixed_pin')
    return raw


def fresh(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'short_write')
    need(path.read_bytes() == raw, 'artifact_readback')


def shape(node):
    return ast.dump(node, include_attributes=False)


def pure_startup(raw):
    tree = ast.parse(raw, feature_version=(3, 5))
    names = ('digest', 'write_new', 'make_source', 'closed_policy')
    nodes = [row for row in tree.body if isinstance(row, ast.FunctionDef) and row.name in names]
    need(tuple(row.name for row in nodes) == names and all(not row.decorator_list for row in nodes),
         'pure_startup_definitions')
    values = {row.targets[0].id: ast.literal_eval(row.value) for row in tree.body
              if isinstance(row, ast.Assign) and len(row.targets) == 1 and
              isinstance(row.targets[0], ast.Name) and row.targets[0].id in ('BEFORE', 'AFTER')}
    need(set(values) == {'BEFORE', 'AFTER'} and all(type(raw) is bytes for raw in values.values()) and
         values['BEFORE'] == b'component=session.run_fixed(artifacts,False,receive_trial_requested=True)' and
         values['AFTER'] == b'component=session.run_fixed(artifacts,False,receive_trial_requested=False)',
         'startup_envelope_literals')
    value = types.ModuleType('fixed_durable_startup_pure')
    value.__dict__.update(values, hashlib=hashlib)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(BASE / DONOR[0]), 'exec'), value.__dict__)
    need('main' not in value.__dict__, 'old_main_forbidden')
    return value


def io_inverse(raw, own):
    tree = ast.parse(raw, feature_version=(3, 5))
    selected = {row.name: shape(row) for row in tree.body if isinstance(row, ast.FunctionDef) and
                row.name in ('metadata', 'read_fixed')}
    current = {row.name: shape(row) for row in ast.parse(own, feature_version=(3, 5)).body
               if isinstance(row, ast.FunctionDef) and row.name in ('metadata', 'read_fixed')}
    need(len(selected) == 2 and selected == current, 'original_io_definition_inverse')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    mode = 'device' if args.check_device else 'source'
    out = BASE / 'results' / ('receive-proc-freezer-v1-startup-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, sealer, evidence = {}, None, None
    helpers = definitions = original = program = component = trials = None
    label = 'receive-proc-freezer-v1-startup'
    report = dict(schema='p011-receive-proc-freezer-v1-startup', mode=mode, passed=False,
        error=None, host_error=None, source_checked=False, source_preserved=False,
        device_invoked=False, host_exit='NOT_RUN', remote_exit='NOT_RUN',
        remote_status_known=False, component=None, trial_facts=None, closed_policy_verified=False,
        old_main_called=False, historical_verify_inputs_called=False, old_tests_executed=False,
        old_builders_executed=False, business_tests_replayed=0, runtime_graph_executed=False,
        target_execution_requested=False,
        policy_requested=False, ui_requested=False, phone_requested=False, rf_action_requested=False,
        ble_listen_requested=False, advertising_requested=False, wifi_action_requested=False,
        http_request_issued=False, local_http_listener_expected=True, pending_handled=False,
        filecenter_created=False, credentials_created=False, production_sources_modified=False,
        actual_startup_performance_verified=False, full_network_restore_verified=False,
        original_activity_seconds=60, original_cleanup_seconds=60, startup_seconds=10,
        remote_alarm_seconds=240, host_timeout_seconds=250, source_cap=2097152, target_line_cap=256,
        payload_cap=4194304, filecenter_cap=131072, envelope_literal_delta_count=1)

    def retain(path, raw):
        if evidence is not None:
            evidence._retain(path, raw)
        elif path in inputs:
            need(inputs[path] == raw, 'input_changed')
        else:
            inputs[path] = raw
        return raw

    def read(path, pin=None):
        # The donor's original IO gates precede any evidence copy or pin rejection.
        raw = read_fixed(path)
        retain(path, raw)
        if pin is not None and (len(raw), digest(raw)) != tuple(pin):
            raise ValueError('fixed_pin')
        return raw

    def fixed(pin):
        return read(pin[0], pin[1:])

    try:
        need(sys.platform == 'win32' and BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'),
             'fixed_pc_identity')
        sealer_raw = fixed(SEALER)
        sealer = types.ModuleType('fixed_durable_startup_sealer')
        exec(compile(sealer_raw, str(BASE / SEALER[0]), 'exec'), sealer.__dict__)
        evidence = sealer.InputEvidence(inputs)
        own = read(SELF)
        for path in CMDS:
            read(path)
        io_inverse(fixed(IO_DONOR), own)
        pure = pure_startup(fixed(DONOR))
        raw = fixed(DEFINITIONS)
        definitions = types.ModuleType('fixed_durable_startup_graph_interfaces')
        definitions.__file__ = str(BASE / DEFINITIONS[0])
        exec(compile(raw, definitions.__file__, 'exec'), definitions.__dict__)
        need(definitions.STATE_ALIAS == '/tmp/' + ROOT_NAME and
             definitions.STATE_ROOT == '/var/volatile/tmp/' + ROOT_NAME and
             definitions.PAYLOAD_BYTES == PAYLOAD_BYTES and len(definitions.ORIGIN_SOURCE_PINS) == 208,
             'actual_durable_graph')
        # Preserve the original schema-aware load_checker, including its private
        # interactive_window_requested parser-field binding, but never its main.
        helpers, checker_raw = definitions.load_checker()
        need(definitions.CHECKER == IO_DONOR and checker_raw == inputs[IO_DONOR[0]], 'checker_identity')
        retain(definitions.CHECKER[0], checker_raw)
        need(helpers.BASE == BASE and tuple(helpers.BOOL_FIELDS)[-1] == 'interactive_window_requested',
             'original_parser_schema')
        for pin in definitions.ORIGIN_SOURCE_PINS:
            fixed(pin)
        for pin in (definitions.MANIFEST, definitions.PRIVATE_MANIFEST, definitions.RUNNER,
                    definitions.TRANSPORT, definitions.ORIGINAL_MANIFEST, definitions.OLD_PRIVATE_MANIFEST):
            fixed(pin)
        ordinary = definitions.manifest_rows(inputs[definitions.MANIFEST[0]])
        private_rows = definitions.manifest_rows(inputs[definitions.PRIVATE_MANIFEST[0]], private=True)
        payload = ordinary + definitions.HELPERS + private_rows + (definitions.WPA, definitions.MONITOR)
        need(len(ordinary) == len(private_rows) == 35 and len(payload) == 75 and
             len({row[0] for row in payload}) == 75 and
             sum(row[2] for row in payload) == PAYLOAD_BYTES <= 4194304, 'actual_payload_inventory')
        for name, path, size, sha in payload:
            fixed((path, size, sha))
        fc_rows = definitions.FILECENTER_SOURCE_PINS
        need(type(fc_rows) is tuple and len(fc_rows) == 9 and
             sum(row[2] for row in fc_rows) == 113690 <= 131072, 'original_filecenter_budget')
        for name, path, size, sha in fc_rows:
            fixed((path, size, sha))
        need(definitions.verify_inputs(inputs) == 8, 'new_freezer_mechanical_closures')
        original, program = pure.make_source(definitions, helpers, inputs, payload)
        need(type(original) is bytes and type(program) is bytes and len(program) <= 2097152 and
             max(map(len, program.splitlines())) <= 256, 'original_carrier_budget')
        ast.parse(program.decode('ascii'), feature_version=(3, 5))
        fresh(out / 'private-original-service-target.py', original)
        fresh(out / 'private-startup-target.py', program)
        report.update(source_checked=True, source_count=len(inputs), payload_role_count=75,
            ordinary_roles=35, private_roles=35, payload_bytes=PAYLOAD_BYTES, payload_remaining_bytes=2538,
            filecenter_sources=9, filecenter_bytes=113690, flat_origin_pins=208,
            mechanical_closures=8, original_io_definition_inverse_verified=True,
            target_bytes=len(program), target_sha256=digest(program),
            original_target_bytes=len(original), original_target_sha256=digest(original),
            target_max_line_bytes=max(map(len, program.splitlines())))
        if args.check_device:
            transport = helpers.load_transport(inputs[definitions.TRANSPORT[0]])
            adb = transport.Adb(private)
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(240);'
                'exec(sys.stdin.buffer.read(' + str(len(program)) + '))" p011-receive-proc-freezer-v1-startup; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True
            report['target_execution_requested'] = True
            output = adb.run(label, ['shell', command], timeout=250, input_data=program)
            remote, component = helpers.parse_result(output)
            # Retain original parsed component even if strict Trial=None parsing
            # subsequently rejects; that reporting fact cannot upgrade FAIL.
            report.update(remote_status_known=True, remote_exit=remote, component=component,
                          runtime_graph_executed=True)
            trials = definitions.parse_trial_facts(output)
            report.update(trial_facts=trials,
                closed_policy_verified=pure.closed_policy(helpers, component, trials))
    except BaseException as failure:
        report['host_error'] = type(failure).__name__
        report['error'] = type(failure).__name__
        fresh(private / 'host-error.private.txt', traceback.format_exc().encode('utf-8'))
    finally:
        prefix = private / ('01-' + label)
        for tag in ('stdout', 'stderr'):
            path = Path(str(prefix) + '.' + tag + '.raw')
            if path.exists():
                raw = path.read_bytes()
                report[tag + '_bytes'] = len(raw)
                report[tag + '_sha256'] = digest(raw)
                if tag == 'stdout':
                    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
                    exits = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M)
                    report['remote_exit'] = int(exits[0]) if len(exits) == 1 else 'UNKNOWN'
                    report['remote_status_known'] = len(exits) == 1
        path = Path(str(prefix) + '.host-exit')
        if path.exists():
            raw = path.read_text(encoding='ascii').strip()
            report['host_exit'] = int(raw) if re.fullmatch(r'-?\d+', raw) else 'TIMEOUT'
        fresh(private / 'remote-exit', (str(report['remote_exit']) + '\n').encode('ascii'))
        try:
            if evidence is not None:
                evidence.snapshot(out, lambda name: name)
            else:
                for path, raw in inputs.items():
                    fresh(out / 'private-inputs' / path, raw)
            report['source_preserved'] = (bool(inputs) and not (evidence and evidence.partial) and
                program is not None and original is not None and
                all(read_fixed(path) == raw and (out / 'private-inputs' / path).read_bytes() == raw
                    for path, raw in inputs.items()) and
                (out / 'private-startup-target.py').read_bytes() == program and
                (out / 'private-original-service-target.py').read_bytes() == original)
        except BaseException as failure:
            report['source_preserved'] = False
            report['host_error'] = report['host_error'] or type(failure).__name__
            report['error'] = report['error'] or type(failure).__name__
            fresh(private / 'evidence-error.private.txt', traceback.format_exc().encode('utf-8'))
    report['passed'] = (report['source_checked'] and report['source_preserved'] and
        report['host_error'] is None and (not args.check_device or
        report['host_exit'] == 0 and report.get('stderr_bytes') == 0 and
        report['remote_status_known'] and report['remote_exit'] == 0 and
        report['closed_policy_verified'] is True))
    report['input_pins'] = [dict(path=path, bytes=len(raw), sha256=digest(raw),
        complete=evidence is None or path not in evidence.partial) for path, raw in inputs.items()]
    report['checker_exit'] = 0 if report['passed'] else 1
    if sealer is None:
        # Never execute an unpinned sealer, and never publish a PASS before sealing.
        fresh(private / 'unsealed-failure-result.json',
              (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'))
        print(json.dumps(dict(passed=False, mode=mode, error=report['error'],
            result_dir=str(out), public_result_zip=None), sort_keys=True))
        return 1
    sealed = sealer.seal_result(out, report, READ_ME)
    print(json.dumps(dict(passed=sealed['report']['passed'], mode=mode,
        error=sealed['report'].get('error'), result_dir=str(out),
        public_result_zip=str(sealed['archive']) if sealed['archive'] else None,
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
