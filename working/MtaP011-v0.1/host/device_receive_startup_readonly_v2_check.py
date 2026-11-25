"""Fixed startup-readonly v2 P011 diagnostic; SOURCE-authored, not receive admission.

No device access by default. Explicit --check-device --preflight-only performs
only fixed read-only target inspection, no staging/Boot/helper/HTTP start.
Explicit --check-device stages only absent project roots with exclusive creates;
existing conflicts/extras remain untouched. No RF, reset, old-record handling,
phone operation, production publication seal or QML handoff is requested.
The independent State root is created complete in one exclusive staging pass:
ordinary31/private35/native3. Existing incomplete roots are never filled.
The real synchronous Owner startup collection runs before HTTP, with RF gates closed.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import types
import zipfile
import zlib

BASE = Path(__file__).resolve().parents[1]
MANIFEST = ('host/client_receive_startup_readonly_v2_definition_manifest.json', 6972,
            '720948906f3409ae1945fd6174d05b7c9bb9c8c1039ecfcb3fe573a6c3a008fb')
PRIVATE_MANIFEST = ('host/client_receive_startup_readonly_v2_private_source_manifest.json', 8140,
                    'e8c6d342be0c150a31759cc7267de3d77c06644955d351d826e72203b5745e2b')
RUNNER = ('candidate/receive-startup-readonly-v2/runtime/mta_startup_readonly_session.py', 70455,
          '77af46c503d5d63ef2e00bf82c4280175d1dd67d0587b264658e6cd85721de70')
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
HELPERS = (
    ('mta-bluez-helper', 'out/native/mta-bluez-helper', 65832,
     '179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363'),
    ('mta-network-helper', 'out/native/mta-network-helper', 47464,
     'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6'),
)
WPA = ('mta-wpa-supplicant', 'native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant', 1351192,
       'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301')
MODULE_NAMES = (
    'mta_client_executor', 'p011_json', 'mta_protocol', 'mta_storage', 'mta_files',
    'mta_crypto', 'mta_transfer_session', 'mta_dhcp', 'mta_dhcp_server', 'mta_scoped_sockets',
    'mta_transport', 'mta_sender', 'mta_send_worker', 'mta_scan_handoff', 'mta_wifi', 'minhttp',
    'mta_client_control_frame', 'mta_client_connect_handoff', 'mta_client_tmp_alias',
    'mta_client_startup_readonly', 'mta_client_receive_factory', 'mta_client_state_bridge', 'mta_go_deployment',
    'mta_send_preparation', 'mta_go_readonly_parent', 'mta_go_send_publication',
    'mta_go_send_bridge', 'mta_go_readonly_terminal_parent', 'mta_service',
    'mta_client_receive_boot', 'mta_client_service_owner',
)
PRIVATE_MODULE_NAMES = (
    'p011_json', 'mta_ip', 'mta_client_tmp_alias', 'mta_p2p_client_init',
    'mta_client_resource_budget', 'mta_client_proc', 'mta_client_caps',
    'mta_client_caps_transport', 'mta_client_baseline', 'mta_client_journal_codec',
    'mta_client_coordination', 'mta_client_files', 'mta_client_pending', 'mta_client_store',
    'mta_client_process_owner', 'mta_client_launch_registration', 'mta_client_two_phase_lease',
    'mta_p2p_client_ctrl', 'mta_client_wpa_status', 'mta_protocol', 'mta_client_control_frame',
    'mta_client_kernel_proof', 'mta_client_connection', 'mta_client_linux_provider',
    'mta_client_executor', 'mta_dhcp', 'mta_dhcp_client_core', 'mta_dhcp_client',
    'mta_client_dora', 'mta_client_dynamic_ip', 'mta_client_peer', 'mta_scoped_sockets',
    'mta_storage', 'mta_transport', 'mta_client_transfer',
)
BOOL_FIELDS = (
    'platform_validated', 'payload_validated', 'before_baseline_observed',
    'after_baseline_observed', 'stock_hashes_match', 'stock_processes_match',
    'baseline_unchanged', 'preflight_complete', 'stage_verified',
    'boot_loaded', 'owner_started', 'http_verified', 'gates_remained_closed',
    'operation_inventory_idle', 'capability_actors_closed', 'owner_close_called',
    'owner_resources_closed', 'runner_fds_closed', 'client_sockets_closed',
    'complete', 'resource_pending', 'staging_pending', 'private_assets_verified',
    'startup_readonly_called', 'startup_readonly_verified', 'startup_baseline_collected',
    'startup_status_verified', 'startup_resources_closed',
)
COUNT_FIELDS = ('created_directory_count', 'created_file_count', 'runner_opened_fd_count',
                'runner_closed_fd_count', 'client_socket_count', 'http_request_count',
                'capability_actor_count', 'state_conflict_count', 'go_conflict_count',
                'startup_status_count', 'startup_proc_reader_count')
REASONS = ('not_started', 'complete', 'preflight_complete', 'startup_readonly', 'unsupported_platform',
           'payload', 'deadline', 'unsafe_anchor', 'source_changed', 'state_conflict',
           'go_conflict', 'foreign_worker', 'user_directory', 'stock_baseline',
           'baseline_changed', 'stage_io', 'stage_changed', 'namespace_busy',
           'boot', 'owner', 'http', 'gates_changed', 'close', 'unexpected')
FIELDS = frozenset(BOOL_FIELDS + COUNT_FIELDS + ('reason',))
COMMON = ('platform_validated', 'payload_validated', 'before_baseline_observed',
          'after_baseline_observed', 'stock_hashes_match', 'stock_processes_match',
          'baseline_unchanged', 'preflight_complete', 'runner_fds_closed', 'client_sockets_closed')
SERVICE = ('stage_verified', 'boot_loaded', 'owner_started', 'http_verified',
           'gates_remained_closed', 'operation_inventory_idle', 'capability_actors_closed',
           'owner_close_called', 'owner_resources_closed', 'private_assets_verified',
           'startup_readonly_called', 'startup_readonly_verified', 'startup_baseline_collected',
           'startup_status_verified', 'startup_resources_closed')


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


def manifest_rows(raw, private=False):
    names = PRIVATE_MODULE_NAMES if private else MODULE_NAMES
    schema = 'client-receive-directory-v1-private-source' if private else 'client-receive-directory-v1-definitions'
    value = json.loads(raw.decode('ascii'))
    keys = {'schema', 'sources', 'previous_manifest_sha256'} if private else {'schema', 'sources'}
    if (type(value) is not dict or set(value) != keys or
            value['schema'] != schema or
            private and value['previous_manifest_sha256'] !=
            'cbd574b76f9027d4c616dd5e514c8bad2d5d88201a561429f227c2773564066f' or
            type(value['sources']) is not list or len(value['sources']) != len(names)):
        raise ValueError('manifest_schema')
    output, paths = [], set()
    for row, name in zip(value['sources'], names):
        if (type(row) is not dict or set(row) != {'module', 'path', 'bytes', 'sha256'} or
                row['module'] != name or type(row['path']) is not str or
                type(row['bytes']) is not int or not 0 < row['bytes'] <= 2 * 1024 * 1024 or
                type(row['sha256']) is not str or re.fullmatch('[0-9a-f]{64}', row['sha256']) is None or
                not row['path'].endswith('/' + name + '.py') or row['path'] in paths):
            raise ValueError('manifest_row')
        paths.add(row['path']); output.append(('runtime35/' + name if private else name,
                                              row['path'], row['bytes'], row['sha256']))
    return tuple(output)


def chunks(raw):
    encoded = base64.b64encode(zlib.compress(raw)).decode('ascii')
    return '\n'.join('    ' + repr(encoded[index:index + 1024]) for index in range(0, len(encoded), 1024))


TARGET_END = r'''
import base64,hashlib,types,zlib
def fixed_decode(encoded,size,sha):
 if type(size) is not int or not 0<size<=2097152:raise ValueError('payload_budget')
 compressed=base64.b64decode(encoded)
 decoder=zlib.decompressobj();raw=decoder.decompress(compressed,size+1)
 if (len(raw)!=size or decoder.unconsumed_tail or decoder.unused_data or not decoder.eof or
     hashlib.sha256(raw).hexdigest()!=sha):raise ValueError('payload_pin')
 return raw
runner_raw=fixed_decode(RUNNER_ENCODED,RUNNER_PIN[0],RUNNER_PIN[1])
artifacts=tuple((name,size,sha,fixed_decode(encoded,size,sha)) for name,size,sha,encoded in ARTIFACT_ROWS)
runner=types.ModuleType('fixed_startup_readonly_diagnostic')
runner.__file__='<fixed-startup-readonly-stdin>'
exec(runner_raw,runner.__dict__)
component=runner.run_fixed(artifacts,PREFLIGHT_ONLY)
error_detail=runner._RETAINED.private_error_detail()
if error_detail is not None:print('ERROR_DETAIL='+repr(error_detail))
startup_errors=runner._RETAINED.private_startup_error_details()
if startup_errors:print('STARTUP_ERROR_DETAILS='+repr(startup_errors))
print('RESULT='+repr(component))
print('MTA_REMOTE_OK')
raise SystemExit(0 if component['complete'] else 1)
'''


def make_source(inputs, rows, private_rows, preflight_only):
    lines = ['PREFLIGHT_ONLY=' + repr(preflight_only), 'RUNNER_PIN=' + repr(RUNNER[1:]),
             'RUNNER_ENCODED=(' + '\n' + chunks(inputs[RUNNER[0]]) + '\n)', 'ARTIFACT_ROWS=(']
    for name, path, size, sha in rows + HELPERS + private_rows + (WPA,):
        lines.append('    (' + repr(name) + ',' + str(size) + ',' + repr(sha) + ',(')
        lines.append(chunks(inputs[path])); lines.append('    )),')
    lines.append(')')
    source = '\n'.join(lines) + '\n' + TARGET_END
    raw = source.encode('ascii')
    if len(raw) > 2 * 1024 * 1024 or any(len(line) > 2048 for line in raw.splitlines()):
        raise ValueError('target_source_budget')
    return source


def load_transport(raw):
    value = types.ModuleType('closed_service_host_transport')
    value.__file__ = str(BASE / TRANSPORT[0])
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    if Path(value.ADB).resolve() != Path('C:/Program Files/ADB/adb.exe').resolve():
        raise ValueError('transport_identity')
    return value


def parse_result(raw):
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    remote = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M)
    rows = [line[7:] for line in derived.splitlines() if line.startswith('RESULT=')]
    if len(remote) != 1 or derived.splitlines().count('MTA_REMOTE_OK') != 1 or len(rows) != 1:
        raise ValueError('remote_result_unknown')
    component = ast.literal_eval(rows[0])
    if (type(component) is not dict or set(component) != FIELDS or
            any(type(component[key]) is not bool for key in BOOL_FIELDS) or
            any(type(component[key]) is not int or not 0 <= component[key] <= 8192 for key in COUNT_FIELDS) or
            component['reason'] not in REASONS): raise ValueError('result_fields')
    return int(remote[0]), component


def validate_error_detail(value):
    # Preserve raw locally; export only bounded source locations and scalar
    # classifications. Never export exception text/args, locals or file paths.
    trusted = frozenset(MODULE_NAMES + PRIVATE_MODULE_NAMES +
        ('fixed_startup_readonly_diagnostic', 'startup_readonly_private_owner'))
    name = r'[A-Za-z_][A-Za-z0-9_]{0,63}'
    if (type(value) is not dict or set(value) != {'kind', 'code', 'errno', 'trace'} or
            type(value['kind']) is not str or re.fullmatch(name, value['kind']) is None or
            value['code'] is not None and (type(value['code']) is not str or
                re.fullmatch(name, value['code']) is None) or
            value['errno'] is not None and (type(value['errno']) is not int or
                not 1 <= value['errno'] <= 4095) or
            type(value['trace']) is not tuple or len(value['trace']) > 32):
        raise ValueError('error_detail_fields')
    for row in value['trace']:
        if (type(row) is not tuple or len(row) != 3 or row[0] not in trusted or
                type(row[1]) is not str or
                re.fullmatch(r'[A-Za-z_<>][A-Za-z0-9_<>]{0,95}', row[1]) is None or
                type(row[2]) is not int or not 0 < row[2] < 1000000):
            raise ValueError('error_detail_trace')
    return value


def parse_error_details(raw):
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    first = [line[13:] for line in derived.splitlines() if line.startswith('ERROR_DETAIL=')]
    startup = [line[22:] for line in derived.splitlines() if line.startswith('STARTUP_ERROR_DETAILS=')]
    if (len(first) > 1 or len(startup) > 1 or
            any(len(row) > 16384 for row in first) or any(len(row) > 131072 for row in startup)):
        raise ValueError('error_detail_unknown')
    detail = validate_error_detail(ast.literal_eval(first[0])) if first else None
    values = ast.literal_eval(startup[0]) if startup else ()
    if type(values) is not tuple or len(values) > 16:
        raise ValueError('startup_error_fields')
    return detail, tuple(validate_error_detail(value) for value in values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    parser.add_argument('--preflight-only', action='store_true')
    args = parser.parse_args()
    if args.preflight_only and not args.check_device:
        parser.error('--preflight-only requires explicit --check-device')
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    mode = ('preflight' if args.preflight_only else 'service' if args.check_device else 'source')
    out = BASE / 'results' / ('startup-readonly-v2-' + mode + '-' + stamp + '-' + secrets.token_hex(4))
    private = out / 'private-raw'; private.mkdir(parents=True, exist_ok=False)
    inputs, rows, private_rows, expected_input_count = {}, (), (), 0
    report = dict(schema='p011-receive-startup-readonly-v2', mode=mode, passed=False,
        source_preserved=False, source_check_complete=False, host_error=None,
        device_invoked=False, host_exit=None, remote_exit=None, remote_status_known=False,
        stdout_bytes=None, stdout_sha256=None, stderr_bytes=None, stderr_sha256=None,
        component_result=None, error_detail=None, startup_error_details=(),
        rf_requested=False, pending_removed=False,
        receive_admission=False, send_admission=False, phone_tested=False,
        qml_handoff=False, full_network_restore_verified=False,
        device_file_writes_requested=args.check_device and not args.preflight_only,
        state_unknown_extras_refused=True, go_siblings_preserved=True,
        whole_tree_atomicity_claimed=False)
    label = 'startup-readonly-v2'
    try:
        fixed = (MANIFEST, PRIVATE_MANIFEST, RUNNER, TRANSPORT)
        for path, size, sha in fixed: inputs[path] = read_fixed(path, (size, sha))
        rows = manifest_rows(inputs[MANIFEST[0]])
        private_rows = manifest_rows(inputs[PRIVATE_MANIFEST[0]], private=True)
        payload_rows = rows + HELPERS + private_rows + (WPA,)
        if sum(row[2] for row in payload_rows) > 4 * 1024 * 1024: raise ValueError('payload_budget')
        for name, path, size, sha in payload_rows:
            raw = read_fixed(path, (size, sha))
            if path in inputs and inputs[path] != raw: raise ValueError('input_shared_changed')
            inputs[path] = raw
        for path in ('host/device_receive_startup_readonly_v2_check.py', 'TEST_MTA_RECEIVE_STARTUP_READONLY_V2.cmd'):
            inputs[path] = read_fixed(path)
        expected_input_count = len({row[0] for row in fixed} | {row[1] for row in payload_rows} |
                                   {'host/device_receive_startup_readonly_v2_check.py', 'TEST_MTA_RECEIVE_STARTUP_READONLY_V2.cmd'})
        for path, raw in inputs.items():
            target = out / 'private-inputs' / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as handle: handle.write(raw)
        # Only changed v2 roles, this runner and this envelope get new AST checks.
        # No old definition AST or passed test is replayed.
        changed = tuple(path for name, path, size, sha in rows
            if path.startswith('candidate/receive-startup-readonly-v2/runtime/'))
        if len(changed) != 6: raise ValueError('changed_role_count')
        for path in changed:
            ast.parse(inputs[path].decode('utf-8'), feature_version=(3, 5))
        report['new_target_runtime_ast_count'] = len(changed)
        report['old_target_runtime_ast_count'] = 0
        ast.parse(inputs[RUNNER[0]].decode('utf-8'), feature_version=(3, 5))
        program = make_source(inputs, rows, private_rows, args.preflight_only)
        ast.parse(program, feature_version=(3, 5))
        data = program.encode('ascii')
        with (out / 'private-target-source.py').open('xb') as handle: handle.write(data)
        report.update(source_check_complete=True, target_source_bytes=len(data),
                      target_source_sha256=digest(data), source_count=len(inputs),
                      fixed_role_count=len(rows), helper_count=len(HELPERS),
                      private_role_count=len(private_rows), private_native_count=1,
                      payload_role_count=len(payload_rows))
        if args.check_device:
            transport = load_transport(inputs[TRANSPORT[0]])
            adb = transport.Adb(private)
            # A single fixed alarm begins before stdin. Activity cap is 60s;
            # original Owner cleanup may use another 60s, not truncated by 180s.
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(180);'
                'exec(sys.stdin.buffer.read(' + str(len(data)) + '))" p011-startup-readonly-v2-check; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True
            raw = adb.run(label, ['shell', command], timeout=210, input_data=data)
            remote, component = parse_result(raw)
            report.update(remote_status_known=True, remote_exit=remote, component_result=component)
    except Exception as error:
        report['host_error'] = type(error).__name__
    finally:
        prefix = private / ('01-' + label)
        host_path = Path(str(prefix) + '.host-exit')
        if host_path.exists():
            raw = host_path.read_text(encoding='ascii').strip()
            report['host_exit'] = int(raw) if re.fullmatch(r'-?\d+', raw) else 'TIMEOUT'
        stdout_path = Path(str(prefix) + '.stdout.raw')
        stderr_path = Path(str(prefix) + '.stderr.raw')
        for stream, path in (('stdout', stdout_path), ('stderr', stderr_path)):
            if path.exists():
                original = path.read_bytes()
                report[stream + '_bytes'] = len(original); report[stream + '_sha256'] = digest(original)
        marker = 'NOT_INVOKED' if not report['device_invoked'] else 'UNKNOWN'
        if stdout_path.exists():
            derived = stdout_path.read_bytes().decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
            found = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M)
            if len(found) == 1:
                report['remote_exit'] = int(found[0]); report['remote_status_known'] = True; marker = found[0]
            try:
                report['error_detail'], report['startup_error_details'] = parse_error_details(stdout_path.read_bytes())
            except (SyntaxError, ValueError, TypeError):
                report['host_error'] = 'ErrorDetailUnknown'
        with Path(str(prefix) + '.remote-exit').open('x', encoding='ascii') as handle: handle.write(marker + '\n')
        try:
            report['source_preserved'] = (expected_input_count > 0 and len(inputs) == expected_input_count and all(
                read_fixed(path) == raw and (out / 'private-inputs' / path).read_bytes() == raw
                for path, raw in inputs.items()))
        except (OSError, ValueError): report['source_preserved'] = False
    component = report['component_result']
    if not args.check_device:
        report['passed'] = report['host_error'] is None and report['source_check_complete'] and report['source_preserved']
    else:
        report['passed'] = (report['host_error'] is None and report['source_check_complete'] and
            report['source_preserved'] and report['host_exit'] == 0 and report['stderr_bytes'] == 0 and
            report['remote_status_known'] and report['remote_exit'] == 0 and type(component) is dict and
            component['complete'] is True and component['resource_pending'] is False and
            component['staging_pending'] is False and all(component[key] for key in COMMON) and
            (args.preflight_only and component['reason'] == 'preflight_complete' and
             component['created_directory_count'] == component['created_file_count'] == 0 and
             not any(component[key] for key in SERVICE if key != 'private_assets_verified') and
             component['http_request_count'] == component['client_socket_count'] ==
             component['capability_actor_count'] == component['startup_status_count'] ==
             component['startup_proc_reader_count'] == 0 or
             not args.preflight_only and component['reason'] == 'complete' and
             all(component[key] for key in SERVICE) and component['http_request_count'] == 9 and
             component['client_socket_count'] == 9 and component['capability_actor_count'] == 2 and
             component['startup_status_count'] == 2 and component['startup_proc_reader_count'] == 3))
    public = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (b'Fixed ordinary31/private35/native3 startup-readonly diagnostic. Source mode does not access ADB. '
        b'Preflight-only mode observes fixed roots, exact existing bytes/modes and limited baseline without '
        b'Boot/native capability/staging/HTTP. Service mode exclusively creates absent project directories/files; '
        b'conflicts and unknown State entries are retained. Existing GO siblings are preserved; only used '
        b'anchors/deployment are checked, not the complete GO graph. Individual creations are exclusive, '
        b'not an atomic whole-tree transaction. Partial new trees remain for diagnosis. '
        b'Existing State roots must already be complete/exact; no fill/repair mode. A missing root gets '
        b'all ordinary/private/native fixed assets in a single exclusive stage with original readback. '
        b'This v2 changes only explicit root-process discovery before managed comm reads; selected daemon '
        b'identity/authentication and all managed-anchor policies remain unchanged. Real canonical Boot29 '
        b'and original synchronous Owner startup collector/STATUS are required. '
        b'Owner/State native capability actors, loopback HTTP and original close '
        b'inventories are required for service PASS. Client sockets/FDs are separately retained and once-closed. '
        b'Token and user file-list responses stay in target memory; they are not printed or archived. '
        b'Single target alarm180/host timeout210, activity60/original cleanup60; timeout/missing markers '
        b'never proves closure. No RF, pending removal, reboot, production seal/admission, QML handoff, '
        b'actual receive/send, phone interoperability or full network restoration claim. '
        b'Raw outputs, original errors/exit markers and fixed snapshots remain local/private.\n')
    with (out / 'result.json').open('xb') as handle: handle.write(public)
    with (out / 'README.txt').open('xb') as handle: handle.write(readme)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public); bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(archive) as bundle:
        if (bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None or
                bundle.read('result.json') != public or bundle.read('README.txt') != readme):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out),
        result_zip=str(archive), zip_sha256=digest(archive.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
