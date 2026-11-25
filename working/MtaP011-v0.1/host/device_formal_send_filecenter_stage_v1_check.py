"""Fixed SOURCE-output asset staging; default local only, explicit --stage once.

No old generator, graph, Boot, Owner, native helper, UI or RF is executed.
An explicit stage first requires a real shell -T no-PTY stdin handshake. There
is no PTY fallback, retry, conflict cleanup, CLIENT access or permission repair.
Raw output/source copies remain private. Public ZIP has result and README only.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import types
import zipfile


BASE = Path(__file__).resolve().parents[1]
SOURCE_DIR = 'results/formal-send-filecenter-deploy-source-20261004-210122-75000000'
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
SOURCE_RESULT = ('result.json', 2443,
                 '26e832421c557778c4dd43233ced27f8262cde4c56de76b8493b667ecc87db2e')
PROFILES = (
    ('sender', 27, 2402458, 77464,
     '7ee89666d129646e0b926e22200d20634f5aaf703989f990c66033d301391df7',
     1218562, '7658efbe12a20b7fecb1302e90659cf64cab5157fb6268cb2cbd126a9a718ed0'),
    ('observer', 41, 1440449, 77466,
     'fa26591d9833188c1535027e629cf20a7e1c0a2c57162261a40741911b70a46c',
     475365, '569af62782d444ff2be330000d7f0f85ce1c5b30698e767ba6bef3d7797aabb7'),
    ('ordinary', 37, 1345955, 77466,
     '050247ef8252c0f7c0cbd6b557bf29b95faaac903cff2c352faf08a439c7e8fd',
     490491, '1c99d183ced7942292ae23131d214d4dae1103f04e648cada091f836fe2e2a34'),
)
SELF = 'host/device_formal_send_filecenter_stage_v1_check.py'
CMD = 'TEST_MTA_FORMAL_SEND_FILECENTER_STAGE_V1.cmd'
CHANNEL_INPUT = b'MTA_STAGE_NO_PTY_V1\n'
STAGE_BOOL_FIELDS = ('stage_complete', 'resource_pending', 'staging_pending',
    'existing_complete', 'receive', 'send', 'boot', 'owner', 'helper', 'rf',
    'restoration', 'phone', 'payload_framed_end_verified',
    'physical_stdin_eof_verified', 'source_only_template')
STAGE_COUNTS = ('original_fds', 'original_fds_closed', 'created_files',
                'created_directories', 'prerequisites', 'service_parent_count')
BOOT_BOOL_FIELDS = ('program_verified', 'program_exec_called', 'program_returned',
    'original_stage_complete', 'original_stage_resources_closed', 'resource_pending',
    'outer_timer_installed', 'outer_timer_released', 'outer_timer_unknown',
    'payload_framed_end_verified', 'physical_stdin_eof_verified')
STAGE_FIELDS = frozenset(STAGE_BOOL_FIELDS + STAGE_COUNTS + ('kind', 'profile'))
BOOT_FIELDS = frozenset(BOOT_BOOL_FIELDS +
                       ('profile', 'inner_seconds', 'outer_seconds', 'error_kind'))
ERROR_CODES = frozenset(('input_pin', 'source_result', 'source_budget', 'transport_pin',
    'channel_unconfirmed', 'remote_status_unknown', 'remote_result', 'stage_refused',
    'stock_baseline', 'stock_changed', 'host_transport', 'source_changed', 'unexpected'))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if not value:
        raise ValueError(code)


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'source_changed')
    need(path.read_bytes() == raw, 'source_changed')


def read_input(inputs, path, size=None, sha=None):
    raw = (BASE / path).read_bytes()
    inputs[path] = raw
    if size is not None:
        need(len(raw) == size and digest(raw) == sha, 'input_pin')
    return raw


def local_inputs(inputs):
    source = read_input(inputs, SOURCE_DIR + '/' + SOURCE_RESULT[0], *SOURCE_RESULT[1:])
    value = json.loads(source)
    need(type(value) is dict and value.get('passed') is True and
         value.get('source_complete') is True and value.get('source_preserved') is True and
         value.get('stage_executed') is False and value.get('graph_executed') is False and
         value.get('device') is False and value.get('program_limit') == 2097152 and
         value.get('decoded_limit') == 4194304 and value.get('wire_limit') == 4194304 and
         value.get('line_limit') == 256 and value.get('inner_seconds') == 120 and
         value.get('outer_seconds') == 180 and type(value.get('batches')) is list and
         len(value['batches']) == 3, 'source_result')
    payloads = {}
    for row, observed in zip(PROFILES, value['batches']):
        profile, files, decoded, program_size, program_sha, wire_size, wire_sha = row
        need(type(observed) is dict and observed.get('profile') == profile and
             observed.get('files') == files and observed.get('decoded_bytes') == decoded and
             observed.get('bootstrap_bytes') == program_size and
             observed.get('bootstrap_sha256') == program_sha and
             observed.get('wire_bytes') == wire_size and observed.get('wire_sha256') == wire_sha,
             'source_result')
        program = read_input(inputs, SOURCE_DIR + '/' + profile + '.bootstrap.py', program_size, program_sha)
        wire = read_input(inputs, SOURCE_DIR + '/' + profile + '.wire.raw', wire_size, wire_sha)
        need(len(program) <= 2097152 and len(wire) <= 4194304 and decoded <= 4194304 and
             all(len(line) <= 256 for line in program.splitlines()) and
             all(len(line) <= 256 for line in wire.splitlines()), 'source_budget')
        program.decode('ascii')
        wire.decode('ascii')
        payloads[profile] = (program, wire)
    read_input(inputs, *TRANSPORT)
    read_input(inputs, SELF)
    read_input(inputs, CMD)
    return payloads


def load_transport(raw):
    module = types.ModuleType('formal_send_filecenter_stage_transport_private')
    module.__file__ = str(BASE / TRANSPORT[0])
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    need(Path(module.ADB).resolve() == Path('C:/Program Files/ADB/adb.exe').resolve(), 'transport_pin')
    return module


def attach_no_pty_transport(adb, transport):
    original_run = transport.Adb.run

    def run(self, label, arguments, timeout=30, input_data=None):
        # Actual Adb.python is reused, but never its plain-shell/PTY fallback.
        if (label in ('stock-before', 'stock-after') and len(arguments) == 2 and
                arguments[0] == 'shell' and input_data is None):
            need(len(arguments[1].encode('ascii')) <= 3500, 'source_budget')
            arguments = ['shell', '-T', arguments[1]]
        else:
            need(len(arguments) == 3 and arguments[:2] == ['shell', '-T'] and
                 label in ('no-pty-channel', 'fixed-asset-stage') and
                 len(arguments[2].encode('ascii')) <= 2048, 'channel_unconfirmed')
        return original_run(self, label, arguments, timeout, input_data)

    adb.run = types.MethodType(run, adb)
    return adb


def stock_identity(value, pins):
    need(type(value) is dict and set(value) == {'stock', 'capabilities'} and
         type(value['stock']) is dict and type(value['capabilities']) is dict and
         type(value['stock'].get('processes')) is list and
         type(value['capabilities'].get('wifi_connected')) is bool, 'stock_baseline')
    rows = value['stock']['processes']
    return (value['stock'].get('hashes') == pins and
        all(len([row for row in rows if type(row) is dict and row.get('name') == name]) == 1
            for name in ('Z03', 'control_engine', 'weston')) and
        all(row.get('exe') == '/usr/bin/' + row['name'] for row in rows
            if type(row) is dict and row.get('name') in ('Z03', 'control_engine')))


def observe_stock(adb, transport, private, phase, report):
    label = 'stock-' + phase
    stem = '%02d-%s' % (adb.index + 1, label)
    try:
        value = transport.Adb.python(adb, label, transport.source(), timeout=45)
        stock_identity(value, transport.PINS)
        write_new(private / (label + '.private.json'),
                  (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii'))
        report['wifi_connected_' + phase] = value['capabilities']['wifi_connected']
    finally:
        report['baseline_' + phase + '_receipt'], ignored = raw_receipt(private, stem, 'MTA_REMOTE_EXIT')
    receipt = report['baseline_' + phase + '_receipt']
    need(receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
         receipt['remote_status_known'] and receipt['remote_exit'] == 0, 'stock_baseline')
    return value


def normalized(raw):
    # Derivative only. Exact bytes are retained by the original Adb.run.
    return raw.decode('ascii', 'strict').replace('\r\r\n', '\n').replace('\r\n', '\n')


def channel_command():
    code = ('import hashlib,os,signal,sys;signal.signal(signal.SIGALRM,signal.SIG_DFL);'
            'signal.alarm(3);p=sys.stdin.buffer.read(' + str(len(CHANNEL_INPUT)) + ');'
            'assert not os.isatty(0) and len(p)==' + str(len(CHANNEL_INPUT)) +
            ' and hashlib.sha256(p).hexdigest()==\'' + digest(CHANNEL_INPUT) + '\';'
            'signal.alarm(0);print(\'MTA_STAGE_CHANNEL_OK=1\')')
    return ('/usr/bin/python3.5 -I -B -c "' + code + '"; r=$?; '
            'printf \'\\nMTA_STAGE_CHANNEL_EXIT=%s\\n\' "$r"')


def stage_command(row):
    code = ('import hashlib,signal,sys;signal.signal(signal.SIGALRM,signal.SIG_DFL);'
            'signal.alarm(20);p=sys.stdin.buffer.read(' + str(row[3]) + ');'
            'assert len(p)==' + str(row[3]) +
            ' and hashlib.sha256(p).hexdigest()==\'' + row[4] + '\';'
            'signal.alarm(0);exec(compile(p,\'<fixed-formal-send-filecenter-stage>\',\'exec\'),'
            '{\'__name__\':\'formal_send_filecenter_stage_fixed_entry\'})')
    command = ('/usr/bin/python3.5 -I -B -c "' + code + '"; r=$?; '
               'if [ "$r" -eq 0 ]; then printf \'MTA_STAGE_REMOTE_OK=1\\n\'; fi; '
               'printf \'\\nMTA_STAGE_REMOTE_EXIT=%s\\n\' "$r"')
    need(len(command.encode('ascii')) <= 2048, 'source_budget')
    return command


def raw_receipt(private, stem, marker):
    receipt = dict(host_exit=None, stdout_bytes=0, stdout_sha256=digest(b''),
                   stderr_bytes=0, stderr_sha256=digest(b''), remote_status_known=False, remote_exit=None)
    stdout = b''
    path = private / (stem + '.host-exit')
    if path.exists():
        value = path.read_text(encoding='ascii').strip()
        receipt['host_exit'] = int(value) if re.fullmatch(r'-?\d+', value) else 'TIMEOUT'
    for stream in ('stdout', 'stderr'):
        path = private / (stem + '.' + stream + '.raw')
        if path.exists():
            raw = path.read_bytes()
            receipt[stream + '_bytes'], receipt[stream + '_sha256'] = len(raw), digest(raw)
            if stream == 'stdout':
                stdout = raw
    remote = 'UNKNOWN'
    try:
        matches = re.findall(r'^' + marker + r'=(-?\d+)$', normalized(stdout), re.M)
        if len(matches) == 1 and len(matches[0]) <= 12:
            receipt['remote_status_known'], receipt['remote_exit'] = True, int(matches[0])
            remote = matches[0]
    except (UnicodeError, ValueError):
        pass
    write_new(private / (stem + '.remote-exit'), (remote + '\n').encode('ascii'))
    return receipt, stdout


def parse_results(raw, profile):
    need(len(raw) <= 1048576, 'remote_result')
    lines = normalized(raw).splitlines()
    values = []
    for prefix, fields, booleans in (
            ('STAGE_RESULT=', STAGE_FIELDS, STAGE_BOOL_FIELDS),
            ('BOOTSTRAP_RESULT=', BOOT_FIELDS, BOOT_BOOL_FIELDS)):
        selected = [line[len(prefix):] for line in lines if line.startswith(prefix)]
        need(len(selected) == 1 and len(selected[0]) <= 8192, 'remote_result')
        value = ast.literal_eval(selected[0])
        need(type(value) is dict and frozenset(value) == fields and value.get('profile') == profile and
             all(type(value[key]) is bool for key in booleans), 'remote_result')
        values.append(value)
    stage, bootstrap = values
    need(stage['kind'] == 'formal-send-stage-v1-files-only' and
         all(type(stage[key]) is int and 0 <= stage[key] <= 1000000 for key in STAGE_COUNTS) and
         type(bootstrap['inner_seconds']) is int and bootstrap['inner_seconds'] == 120 and
         type(bootstrap['outer_seconds']) is int and bootstrap['outer_seconds'] == 180 and
         (bootstrap['error_kind'] is None or type(bootstrap['error_kind']) is str and
          re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', bootstrap['error_kind']) is not None), 'remote_result')
    return stage, bootstrap, lines.count('MTA_STAGE_REMOTE_OK=1')


def completed(stage, bootstrap, row):
    return (stage['stage_complete'] and not stage['resource_pending'] and not stage['staging_pending'] and
        stage['original_fds_closed'] == stage['original_fds'] and stage['created_files'] <= row[1] and
        stage['payload_framed_end_verified'] and not stage['physical_stdin_eof_verified'] and
        not stage['source_only_template'] and all(stage[key] is False for key in
            ('boot', 'owner', 'helper', 'receive', 'send', 'rf', 'restoration', 'phone')) and
        all(bootstrap[key] is True for key in ('program_verified', 'program_exec_called', 'program_returned',
            'original_stage_complete', 'original_stage_resources_closed', 'outer_timer_installed',
            'outer_timer_released', 'payload_framed_end_verified')) and
        all(bootstrap[key] is False for key in
            ('resource_pending', 'outer_timer_unknown', 'physical_stdin_eof_verified')) and
        bootstrap['error_kind'] is None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=tuple(row[0] for row in PROFILES),
                        help='Explicitly stage one fixed assets-only batch; never starts a service.')
    args = parser.parse_args()
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
    out = BASE / 'results' / ('formal-send-filecenter-stage-v1-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'
    private.mkdir()
    inputs = {}
    adb = transport = before = after = None
    report = dict(kind='formal-send-filecenter-stage-v1', passed=False, mode='stage' if args.stage else 'local',
        profile=args.stage, local_inputs_verified=False, source_preserved=False, input_count=0,
        channel_invoked=False, channel_confirmed=False, stage_invoked=False,
        stage_execution_unknown=False, channel_receipt=None, stage_receipt=None,
        baseline_before_receipt=None, baseline_after_receipt=None,
        stock_identity_ok=None, stock_unchanged=None,
        wifi_connected_before=None, wifi_connected_after=None,
        stage_result=None, bootstrap_result=None, error_code=None,
        authorized_asset_only=True, boot_owner_or_rf_requested=False,
        partial_inventory_policy='preserve-no-retry', physical_stdin_eof_verified=False)
    try:
        payloads = local_inputs(inputs)
        report['local_inputs_verified'] = True
        for path, raw in inputs.items():
            write_new(out / 'private-inputs' / path, raw)
        if args.stage:
            transport = load_transport(inputs[TRANSPORT[0]])
            adb = attach_no_pty_transport(transport.Adb(private), transport)
            write_new(private / 'stock-source.private.py', transport.source().encode('ascii'))
            command = channel_command()
            need(len(command.encode('ascii')) <= 2048, 'source_budget')
            write_new(private / 'channel-command.private', command.encode('ascii'))
            report['channel_invoked'] = True
            channel_stem = '%02d-no-pty-channel' % (adb.index + 1)
            try:
                raw = adb.run('no-pty-channel', ['shell', '-T', command], timeout=10, input_data=CHANNEL_INPUT)
                need(normalized(raw) == 'MTA_STAGE_CHANNEL_OK=1\n\nMTA_STAGE_CHANNEL_EXIT=0\n',
                     'channel_unconfirmed')
                report['channel_confirmed'] = True
            finally:
                report['channel_receipt'], ignored = raw_receipt(
                    private, channel_stem, 'MTA_STAGE_CHANNEL_EXIT')
            receipt = report['channel_receipt']
            need(receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                 receipt['remote_status_known'] and receipt['remote_exit'] == 0, 'channel_unconfirmed')
            before = observe_stock(adb, transport, private, 'before', report)
            report['stock_identity_ok'] = stock_identity(before, transport.PINS)
            need(report['stock_identity_ok'], 'stock_baseline')
            row = next(row for row in PROFILES if row[0] == args.stage)
            command = stage_command(row)
            write_new(private / 'stage-command.private', command.encode('ascii'))
            program, wire = payloads[args.stage]
            report['stage_invoked'] = report['stage_execution_unknown'] = True
            stage_stem = '%02d-fixed-asset-stage' % (adb.index + 1)
            stage_call_error = None
            try:
                adb.run('fixed-asset-stage', ['shell', '-T', command], timeout=210, input_data=program + wire)
            except BaseException as error:
                stage_call_error = error
            finally:
                report['stage_receipt'], raw = raw_receipt(private, stage_stem, 'MTA_STAGE_REMOTE_EXIT')
            try:
                stage, bootstrap, ok_count = parse_results(raw, args.stage)
            except BaseException:
                if stage_call_error is not None:
                    raise stage_call_error
                raise
            report['stage_result'], report['bootstrap_result'] = stage, bootstrap
            receipt = report['stage_receipt']
            if type(receipt['host_exit']) is int and receipt['remote_status_known']:
                report['stage_execution_unknown'] = False
            if stage_call_error is not None:
                raise stage_call_error
            need(receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                 receipt['remote_status_known'], 'remote_status_unknown')
            need(receipt['remote_exit'] == 0 and ok_count == 1 and completed(stage, bootstrap, row), 'stage_refused')
    except BaseException as error:
        report['error_code'] = error.args[0] if (type(error) is ValueError and len(error.args) == 1 and
            type(error.args[0]) is str and error.args[0] in ERROR_CODES) else (
            'host_transport' if type(error) is RuntimeError else 'unexpected')
    finally:
        # A rejected tiny marker or failed stage still gets one readonly after
        # observation. It neither retries a stage nor clears the first error.
        if adb is not None:
            try:
                after = observe_stock(adb, transport, private, 'after', report)
                report['stock_identity_ok'] = (before is not None and
                    stock_identity(before, transport.PINS) and stock_identity(after, transport.PINS))
                report['stock_unchanged'] = before is not None and before['stock'] == after['stock']
                need(report['stock_identity_ok'] and report['stock_unchanged'], 'stock_changed')
            except BaseException as error:
                if report['error_code'] is None:
                    report['error_code'] = error.args[0] if (type(error) is ValueError and len(error.args) == 1 and
                        type(error.args[0]) is str and error.args[0] in ERROR_CODES) else 'stock_baseline'
        inventory = {}
        preserved = bool(inputs)
        for path, raw in inputs.items():
            try:
                destination = out / 'private-inputs' / path
                if not destination.exists():
                    write_new(destination, raw)
                inventory[path] = dict(bytes=len(raw), sha256=digest(raw))
                if (BASE / path).read_bytes() != raw or destination.read_bytes() != raw:
                    preserved = False
            except BaseException:
                preserved = False
        report['source_preserved'], report['input_count'] = preserved, len(inputs)
        write_new(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
    report['passed'] = (report['local_inputs_verified'] and report['source_preserved'] and
                        report['error_code'] is None and (not args.stage or report['stage_invoked'] and
                        not report['stage_execution_unknown'] and report['stock_identity_ok'] is True and
                        report['stock_unchanged'] is True))
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Fixed existing SOURCE artifacts only; default local check never contacts ADB.\n'
        b'Explicit --stage runs one assets-only fixed batch after a shell -T stdin/no-echo confirmation.\n'
        b'No PTY fallback, retry, CLIENT/pending processing, overwrite, removal or permission repair.\n'
        b'Program read has an actual 20s SIGALRM; pinned bootstrap retains inner120/outer180 and host210.\n'
        b'Raw stdout/stderr, independent remote/host exits and source copies remain private.\n'
        b'Original fixed readonly stock/process/wifi/ConnMan/BlueZ probes run before and after; private facts stay local.\n'
        b'Adb.python plain-shell/stdin fallback is refused; every accepted shell command uses -T.\n'
        b'Public stage/bootstrap dictionaries are strict parsed actual outputs, not inferred readiness.\n'
        b'Framed end is not physical stdin EOF. Timeout/unknown output never proves resource closure.\n'
        b'Only fixed assets may be created. No Boot/Owner/native helper/UI/RF is started.\n'
        b'Not evidence of file transfer, restoration, guardian operation or phone interoperability.\n')
    write_new(out / 'result.json', result)
    write_new(out / 'README.txt', readme)
    with zipfile.ZipFile(out / 'RESULTS.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result)
        archive.writestr('README.txt', readme)
    with zipfile.ZipFile(out / 'RESULTS.zip') as archive:
        need(archive.namelist() == ['result.json', 'README.txt'] and archive.testzip() is None and
             archive.read('result.json') == result and archive.read('README.txt') == readme, 'source_changed')
    print(json.dumps(dict(passed=report['passed'], mode=report['mode'], result_dir=str(out)), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
