"""Fixed formal-receive-v1 graph check; default HOST SOURCE only.

SOURCE-authored independent entry. Only --check-device invokes the fixed P011
transport; --ui additionally selects the already-staged immutable copied UI.
No receive admission switch, old smoke suite, old START, RF action, pending-record
handling, UI asset installation or firmware/startup replacement is implemented.
The six changed ordinary roles, runner, worker and two new envelopes receive
syntax/literal cross-pin checks. Unchanged private/parser sources are byte-checked,
not re-executed or retested. This is not a synthetic platform simulation.
Raw streams, original source snapshots and programs stay private/local. The
public ZIP contains only scalar result fields and one fixed explanatory text.
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
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_receive_v1_check.py'
CHECKER = ('host/device_receive_startup_readonly_v4_check.py', 27003,
           '4ed9c5eb9403f81d967cce91bf21d71e2230d82e49e7d8dfb1d178a353311cbf')
MANIFEST = ('host/formal_receive_v1_definition_manifest.json', 7333,
            '333b37ea427438d7e8f506fca6450ea61b9dfeb39b2061e36d50fcb0eb968ab2')
PRIVATE_MANIFEST = ('host/formal_receive_v1_private_source_manifest.json', 8132,
                    '9c089f7e26e4eb8b4aae6bea97b349de7b504e6fa5193c6780ef0fc08a26ffa5')
PREVIOUS_PRIVATE_SHA = 'ae449a5427a3c15f7b4ef7af4db12522de3ae63ec9612f79e466cc5741266457'
RUNNER = ('candidate/formal-receive-v1/runtime/mta_formal_receive_session.py', 73287,
          '3d67fa640e9b16844d938d8da07c51ac863fe611b04bc9b70d646267a304c4a9')
WORKER = ('candidate/formal-receive-v1/runtime/ui_session.py', 45943,
          'e64d4daf7868d4211da64b9e2ea825e89e19dc4dcc52ba6c0ef83b8b065785f6')
VALIDATOR = ('candidate/formal-ui-native-v1/runtime/ui_assets.py', 10489,
             'e58de146a8274402af0535972b8179f1d7a973320f3437935a29212a962e6507')
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
CMDS = (
    ('HOST_MTA_FORMAL_RECEIVE_V1_CHECK.cmd', 243,
     'd3dd8da0050e45e2486858227b54cdb89ab1966c67d53b1ef5ae195ab47d3e4b'),
    ('TEST_MTA_FORMAL_RECEIVE_V1.cmd', 271,
     'd3f7b8cc31f9b2834fefe2fbac06a32ad0b269c74d9b4ccb050c9605cc77174e'),
)
HELPERS = (
    ('mta-bluez-helper',
     'results/receive-radio-baseline-build-20261004-112415-de67547c/mta-bluez-radio-baseline',
     74920, 'c06398ddae281cf4a6f8a41953baf84795992f8f3e3769baebaf11f6d9964181'),
    ('mta-network-helper', 'out/native/mta-network-helper', 47464,
     'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6'),
    ('mta-connman-observer',
     'results/receive-network-observer-build-20261004-120127-0ce26786/mta-connman-observer',
     46008, '5f2612224a3db35d8f0850adf10d1fece7094bff6387521c185570c4be8068e2'),
)
WPA = ('mta-wpa-supplicant', 'native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant',
       1351192, 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301')
MONITOR = ('receive_monitor', 'candidate/formal-ui-receive-monitor-v1/runtime/receive_monitor.py',
           13963, 'fe2a8bab0db21c45c6fe3d0a4733029492c8617d57ddbc9f296888c8c6837e36')
MODULE_NAMES = (
    'mta_client_executor', 'p011_json', 'mta_protocol', 'mta_storage', 'mta_files',
    'mta_crypto', 'mta_transfer_session', 'mta_dhcp', 'mta_dhcp_server', 'mta_scoped_sockets',
    'mta_transport', 'mta_sender', 'mta_send_worker', 'mta_scan_handoff', 'mta_wifi', 'minhttp',
    'mta_client_control_frame', 'mta_client_connect_handoff', 'mta_client_tmp_alias',
    'mta_client_startup_readonly', 'mta_client_receive_factory', 'mta_client_state_bridge',
    'mta_go_deployment', 'mta_send_preparation', 'mta_go_readonly_parent',
    'mta_go_send_publication', 'mta_go_send_bridge', 'mta_go_readonly_terminal_parent',
    'mta_receive_radio_baseline', 'mta_receive_network', 'mta_service',
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
CHANGED_ROLES = ('mta_client_executor', 'mta_client_receive_factory',
                 'mta_client_state_bridge', 'mta_service', 'mta_client_receive_boot',
                 'mta_client_service_owner')
STATE_ALIAS = '/tmp/p011-mta-formal-receive-v1'
STATE_ROOT = '/var/volatile/tmp/p011-mta-formal-receive-v1'
STARTUP_BOOL_FIELDS = ('startup_readonly_called', 'startup_readonly_verified',
                       'startup_baseline_collected', 'startup_status_verified',
                       'startup_resources_closed')
UI_COUNT_FIELDS = ('startup_status_count', 'startup_proc_reader_count')
UI_BOOL_FIELDS = ('complete', 'ui_ready', 'ui_http_observed', 'owner_close_verified',
                  'credentials_removed', 'candidate_exited', 'stock_restored',
                  'guardian_exited', 'worker_fds_closed', 'radio_admission',
                  'original_ui_exited', 'physical_ui_verified', 'resource_pending') + STARTUP_BOOL_FIELDS
UI_FIELDS = frozenset(UI_BOOL_FIELDS + UI_COUNT_FIELDS + ('reason',))
UI_REASONS = (
    'not_started', 'ui_finished', 'session_failed', 'read_budget', 'boot',
    'pid', 'process_stat', 'pid_changed', 'process_unknown', 'process_exec_changed',
    'boot_changed', 'self_signal', 'candidate_identity', 'process_did_not_exit',
    'process_budget', 'foreign_candidate', 'process_race_budget', 'stock_file_identity',
    'hash_budget', 'hash_changed', 'pipe_frame', 'pipe_write', 'pipe_budget',
    'private_core_limit', 'inherited_fd_changed', 'inherited_fd_close',
    'guardian_fd_offset', 'guardian_inherited_fd', 'guardian_stdio',
    'inherited_fd_unknown', 'inherited_fd_duplicate', 'duplicate_close_frame',
    'restore_without_close_report', 'duplicate_candidate_frame', 'candidate_frame',
    'guardian_frame', 'worker_not_stopped', 'candidate_inventory', 'candidate_remains',
    'launcher_missing', 'stock_pins_changed', 'control_changed', 'guardian_after_write',
    'fresh_worker', 'worker_threads', 'source_pin', 'artifacts', 'assets_identity',
    'stop_requested', 'raw_file', 'raw_write', 'raw_close', 'pipe_fd',
    'asset_directory_changed', 'credentials_changed', 'credentials_remove',
    'stock_pins', 'private_assets_required', 'asset_binding', 'other_ui_trial',
    'stock_identity', 'stock_topology', 'stock_ui', 'stock_launcher', 'wayland',
    'fork_boundary', 'guardian_parent_fd_close', 'guardian_not_armed',
    'guardian_armed_frame', 'rf_gate_open', 'credential_pair', 'credential_file',
    'credential_write', 'credential_identity', 'credential_close', 'guardian_missing',
    'launcher_not_stopped', 'candidate_start', 'ui_log_identity', 'ui_writer_close',
    'closed_service_changed', 'ui_log_budget', 'qml_failed', 'qml_ready_timeout',
    'guardian_eof_close', 'guardian_result_frame', 'startup_observation',
)
UI_SUCCESS = ('complete', 'ui_ready', 'ui_http_observed', 'owner_close_verified',
              'credentials_removed', 'candidate_exited', 'stock_restored',
              'guardian_exited', 'worker_fds_closed', 'original_ui_exited') + STARTUP_BOOL_FIELDS
HOST_ERROR_CODES = (
    'checker_ancestor', 'checker_link', 'checker_file', 'checker_identity',
    'checker_changed', 'checker_pin', 'checker_base', 'fixed_path', 'fixed_ancestor',
    'fixed_link', 'fixed_file', 'fixed_identity', 'fixed_changed', 'fixed_pin',
    'pins_not_frozen', 'input_shared_changed', 'manifest_schema', 'manifest_row',
    'payload_budget', 'source_assignment', 'source_literal', 'source_graph',
    'target_source_budget', 'transport_identity', 'remote_result_unknown',
    'result_fields', 'zip_readback',
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _meta(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def load_checker():
    # Only this literal bootstrap file is executed, never its __main__.
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or
                getattr(value, 'st_file_attributes', 0) & 0x400):
            raise ValueError('checker_ancestor')
    path = BASE
    for part in CHECKER[0].split('/'):
        path = path / part
        value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise ValueError('checker_link')
        if path != BASE / CHECKER[0] and not stat.S_ISDIR(value.st_mode):
            raise ValueError('checker_ancestor')
    before = _meta(value)
    if not stat.S_ISREG(value.st_mode) or value.st_size != CHECKER[1]:
        raise ValueError('checker_file')
    with path.open('rb') as handle:
        opened = _meta(os.fstat(handle.fileno()))
        same = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                opened[3:6] == before[3:6]) if os.name == 'nt' else opened == before
        if not same:
            raise ValueError('checker_identity')
        raw = handle.read(CHECKER[1] + 1)
        if _meta(os.fstat(handle.fileno())) != opened:
            raise ValueError('checker_changed')
    if _meta(path.lstat()) != before:
        raise ValueError('checker_changed')
    if (len(raw), digest(raw)) != CHECKER[1:]:
        raise ValueError('checker_pin')
    value = types.ModuleType('fixed_formal_receive_host_helpers')
    value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    if value.BASE != BASE:
        raise ValueError('checker_base')
    return value, raw


def manifest_rows(raw, private=False):
    names = PRIVATE_MODULE_NAMES if private else MODULE_NAMES
    schema = 'client-receive-directory-v1-private-source' if private else 'client-receive-directory-v1-definitions'
    value = json.loads(raw.decode('ascii'))
    keys = {'schema', 'sources', 'previous_manifest_sha256'} if private else {'schema', 'sources'}
    if (type(value) is not dict or set(value) != keys or value['schema'] != schema or
            private and value['previous_manifest_sha256'] != PREVIOUS_PRIVATE_SHA or
            type(value['sources']) is not list or len(value['sources']) != len(names)):
        raise ValueError('manifest_schema')
    rows, paths = [], set()
    for row, name in zip(value['sources'], names):
        if (type(row) is not dict or set(row) != {'module', 'path', 'bytes', 'sha256'} or
                row['module'] != name or type(row['path']) is not str or
                type(row['bytes']) is not int or not 0 < row['bytes'] <= 2 * 1024 * 1024 or
                type(row['sha256']) is not str or re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is None or
                not row['path'].endswith('/' + name + '.py') or row['path'] in paths or
                PurePosixPath(row['path']).is_absolute() or '\\' in row['path'] or
                re.fullmatch(r'[A-Za-z0-9_./-]+', row['path']) is None or
                any(part in ('', '.', '..') for part in row['path'].split('/'))):
            raise ValueError('manifest_row')
        if not private and name in CHANGED_ROLES and row['path'] != (
                'candidate/formal-receive-v1/runtime/' + name + '.py'):
            raise ValueError('manifest_row')
        paths.add(row['path'])
        rows.append(('runtime35/' + name if private else name,
                     row['path'], row['bytes'], row['sha256']))
    return tuple(rows)


def _assignment(tree, name, bindings=None):
    rows = []
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else (
            [node.target] if isinstance(node, ast.AnnAssign) else [])
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            rows.append(node.value)
    if len(rows) != 1:
        raise ValueError('source_assignment')
    bindings = {} if bindings is None else bindings
    def literal(node):
        if isinstance(node, ast.Constant) and type(node.value) in (str, int, bool, type(None)):
            return node.value
        if isinstance(node, ast.Tuple):
            return tuple(literal(value) for value in node.elts)
        if isinstance(node, ast.List):
            return [literal(value) for value in node.elts]
        if isinstance(node, ast.Name) and node.id in bindings:
            return bindings[node.id]
        raise ValueError('source_literal')
    return literal(rows[0])


def check_source_graph(checker, inputs, rows, private_rows, payload):
    # Parse exactly the six changed ordinary sources and two new lifecycle sources.
    # Literal resolution accepts only these named fixed SHA bindings, never eval.
    ordinary = {name: (path, size, sha) for name, path, size, sha in rows}
    trees = {name: ast.parse(inputs[ordinary[name][0]].decode('utf-8'), feature_version=(3, 5))
             for name in CHANGED_ROLES}
    runner = ast.parse(inputs[RUNNER[0]].decode('utf-8'), feature_version=(3, 5))
    worker = ast.parse(inputs[WORKER[0]].decode('utf-8'), feature_version=(3, 5))
    factory = trees['mta_client_receive_factory']
    boot = trees['mta_client_receive_boot']
    owner = trees['mta_client_service_owner']
    executor = trees['mta_client_executor']
    role_pins = tuple((name, size, sha) for name, path, size, sha in rows)
    private_pins = tuple((name.split('/', 1)[1], size, sha) for name, path, size, sha in private_rows)
    source_pins = role_pins[:-2]
    f_sha = ordinary['mta_client_executor'][2]
    actual_checks = (
        _assignment(runner, 'ROLE_PINS') == role_pins,
        _assignment(runner, 'PRIVATE_PINS') == private_pins,
        _assignment(runner, 'HELPER_PINS') == tuple((name, size, sha) for name, path, size, sha in HELPERS),
        _assignment(runner, 'WPA_PIN') == (WPA[0], WPA[2], WPA[3]),
        _assignment(runner, 'MONITOR_PIN') == (MONITOR[0], MONITOR[2], MONITOR[3]),
        _assignment(worker, 'MONITOR_PIN') == (MONITOR[0], MONITOR[2], MONITOR[3]),
        _assignment(worker, 'RUNNER_PIN') == RUNNER[1:],
        _assignment(boot, 'SOURCE_PINS', {'F37_SHA': f_sha}) == source_pins,
        _assignment(factory, 'SOURCE_PINS', {'F_SHA': f_sha}) == private_pins,
        _assignment(boot, 'F37_SHA') == f_sha,
        _assignment(factory, 'F_SHA') == f_sha,
        _assignment(boot, 'CLIENT_MANIFEST_SHA') == PRIVATE_MANIFEST[2],
        _assignment(factory, 'SOURCE_MANIFEST_SHA') == PRIVATE_MANIFEST[2],
        _assignment(owner, 'BOOT_PIN') == ordinary['mta_client_receive_boot'][1:],
        _assignment(owner, 'BOOT_MODULES') == tuple(row[0] for row in source_pins),
        _assignment(owner, 'HELPER_PINS') == tuple((row[2], row[3]) for row in HELPERS[:2]),
        _assignment(owner, 'CONNMAN_PIN') == HELPERS[2][2:],
        _assignment(owner, 'BOOT_SCHEMA') == 'sender-state-boot-v98-source',
        _assignment(boot, 'SOURCE_SCHEMA') == 'sender-state-boot-v98-source',
        _assignment(owner, 'STARTUP_READONLY_SCHEMA') == 'receive-startup-readonly-v1',
        _assignment(factory, 'STARTUP_READONLY_SCHEMA') == 'receive-startup-readonly-v1',
        _assignment(executor, 'ROOT') == '/tmp/p011-mta-client-rfinit',
        _assignment(executor, 'PHYSICAL_ROOT') == '/var/volatile/tmp/p011-mta-client-rfinit',
        tuple(_assignment(runner, 'BOOL_FIELDS')) == tuple(checker.BOOL_FIELDS),
        tuple(_assignment(runner, 'COUNT_FIELDS')) == tuple(checker.COUNT_FIELDS),
        tuple(_assignment(runner, 'REASONS')) == tuple(checker.REASONS),
    )
    if not all(actual_checks):
        raise ValueError('source_graph')
    for tree, logical, physical in (
            (runner, 'STATE_ALIAS', 'STATE_ROOT'), (worker, 'STATE_ALIAS', 'STATE_ROOT'),
            (factory, 'ASSET_ROOT', 'ASSET_PHYSICAL_ROOT'), (boot, 'ROOT', 'PHYSICAL_ROOT')):
        if _assignment(tree, logical) != STATE_ALIAS or _assignment(tree, physical) != STATE_ROOT:
            raise ValueError('source_graph')
    if _assignment(owner, 'ROOT') != STATE_ALIAS:
        raise ValueError('source_graph')
    if tuple(row[0] for row in payload) != (
            tuple(row[0] for row in role_pins) +
            tuple(row[0] for row in HELPERS) +
            tuple('runtime35/' + row[0] for row in private_pins) + (WPA[0], MONITOR[0])):
        raise ValueError('source_graph')
    # No unchanged parser/private graph AST, import or historical test execution.
    return len(trees) + 2


TARGET_COMMON = r'''
import base64,hashlib,re,types,zlib
def fixed_decode(encoded,size,sha):
 if type(size) is not int or not 0<size<=2097152:raise ValueError('payload_budget')
 compressed=base64.b64decode(encoded)
 decoder=zlib.decompressobj();raw=decoder.decompress(compressed,size+1)
 if (len(raw)!=size or decoder.unconsumed_tail or decoder.unused_data or not decoder.eof or
     hashlib.sha256(raw).hexdigest()!=sha):raise ValueError('payload_pin')
 return raw
def fixed_error_details(errors):
 rows=[];seen=set()
 for error in errors:
  if len(rows)>=16:break
  if not isinstance(error,BaseException) or id(error) in seen:continue
  seen.add(id(error));kind='Exception'
  if isinstance(error,OSError):kind='OSError'
  else:
   for cls,name in ((ValueError,'ValueError'),(RuntimeError,'RuntimeError'),
                    (TypeError,'TypeError'),(AttributeError,'AttributeError'),
                    (KeyError,'KeyError'),(IndexError,'IndexError'),
                    (AssertionError,'AssertionError'),(ImportError,'ImportError'),
                    (SyntaxError,'SyntaxError')):
    if isinstance(error,cls):kind=name;break
   if USE_UI and type(error) is session.UiSessionError:kind='UiSessionError'
  code=getattr(error,'code',None)
  code=code if type(code) is str and code in RESULT_REASONS else 'unclassified'
  number=error.errno if isinstance(error,OSError) else None
  number=number if type(number) is int and 1<=number<=4095 else None
  frames=[];tb=error.__traceback__;count=0
  while tb is not None and count<32:
   frame=tb.tb_frame;module=frame.f_globals.get('__name__');name=frame.f_code.co_name;line=tb.tb_lineno
   if (type(module) is str and module in ERROR_MODULES and type(name) is str and
       re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,95}',name) is not None and
       type(line) is int and 1<=line<=1000000):frames.append((module,name,line))
   tb=tb.tb_next;count+=1
  rows.append(dict(kind=kind,code=code,errno=number,trace=tuple(frames)))
 return tuple(rows)
runner_raw=fixed_decode(RUNNER_ENCODED,RUNNER_PIN[0],RUNNER_PIN[1])
artifacts=tuple((name,size,sha,fixed_decode(encoded,size,sha)) for name,size,sha,encoded in ARTIFACT_ROWS)
'''

TARGET_SERVICE = r'''
session=types.ModuleType('fixed_startup_readonly_diagnostic')
session.__file__='<fixed-formal-receive-service-stdin>'
exec(runner_raw,session.__dict__)
try:
 component=session.run_fixed(artifacts,False)
except BaseException as error:
 detail=fixed_error_details((error,))
 if detail:print('ERROR_DETAIL='+repr(detail))
 print('SESSION_ERROR_CODE=service_exception')
 raise SystemExit(2)
retained=session._RETAINED
if component['complete'] is not True and retained is not None:
 errors=[getattr(retained,'first_error',None)]
 scope=getattr(retained,'startup_scope',None)
 errors.append(getattr(scope,'failure',None))
 collection=getattr(retained,'startup_collection',None)
 errors.append(getattr(collection,'failure',None))
 values=getattr(collection,'close_failures',None)
 if type(values) is list:errors.extend(values[:16])
 detail=fixed_error_details(errors)
 if detail:print('ERROR_DETAIL='+repr(detail))
 startup=retained.private_startup_error_details()
 if startup:print('STARTUP_ERROR_DETAILS='+repr(startup))
print('RESULT='+repr(component))
print('MTA_REMOTE_OK')
raise SystemExit(0 if component['complete'] else 1)
'''

TARGET_UI = r'''
worker_raw=fixed_decode(WORKER_ENCODED,WORKER_PIN[0],WORKER_PIN[1])
validator_raw=fixed_decode(VALIDATOR_ENCODED,VALIDATOR_PIN[0],VALIDATOR_PIN[1])
session=types.ModuleType('fixed_formal_ui_session')
session.__file__='<fixed-formal-receive-ui-stdin>'
exec(worker_raw,session.__dict__)
try:
 component=session.run_fixed(runner_raw,artifacts,validator_raw)
except BaseException as error:
 detail=fixed_error_details((error,))
 if detail:print('ERROR_DETAIL='+repr(detail))
 code=(error.code if type(error) is session.UiSessionError and error.code in RESULT_REASONS else 'ui_exception')
 print('UI_ERROR_CODE='+code)
 raise SystemExit(2)
if component['complete'] is not True:
 retained=session._RETAINED;errors=[]
 if type(retained) is dict:
  values=retained.get('failures')
  if type(values) is list:errors.extend(values[:16])
  original=retained.get('component')
  values=getattr(original,'failures',None)
  if type(values) is list:errors.extend(values[:16])
  owner=getattr(original,'owner',None)
  errors.append(getattr(owner,'startup_failure',None))
  scope=getattr(original,'startup_scope',None)
  errors.append(getattr(scope,'failure',None))
  collection=getattr(original,'startup_collection',None)
  errors.append(getattr(collection,'failure',None))
  values=getattr(collection,'close_failures',None)
  if type(values) is list:errors.extend(values[:16])
  values=getattr(collection,'status_rows',None)
  if type(values) is list:
   for row in values[:2]:
    if type(row) is dict:errors.append(row.get('failure'))
 detail=fixed_error_details(errors)
 if detail:print('ERROR_DETAIL='+repr(detail))
print('RESULT='+repr(component))
print('MTA_REMOTE_OK')
raise SystemExit(0 if component['complete'] else 1)
'''


def _short_chunks(checker, raw):
    # Reuse the pinned helper's exact encoder, but not its 1024-character lines.
    # The device transport may traverse a canonical TTY with a 512-byte line cap.
    # Generated ASCII base64 repr is always this one quote shape, not arbitrary
    # input code. Fragment width96 keeps each physical encoded line below128.
    parts = []
    for line in checker.chunks(raw).splitlines():
        if (not line.startswith("    '") or not line.endswith("'") or
                re.fullmatch(r'[A-Za-z0-9+/=]{1,1024}', line[5:-1]) is None):
            raise ValueError('target_source_budget')
        parts.append(line[5:-1])
    encoded = ''.join(parts)
    if not encoded:
        raise ValueError('target_source_budget')
    return '\n'.join('    ' + repr(encoded[index:index + 96])
                     for index in range(0, len(encoded), 96))


def make_source(checker, inputs, payload, use_ui):
    modules = tuple(sorted(set(MODULE_NAMES + PRIVATE_MODULE_NAMES + (
        'fixed_formal_ui_session', 'fixed_formal_ui_runner', 'fixed_formal_ui_assets',
        'fixed_formal_receive_monitor', 'fixed_startup_readonly_diagnostic',
        'startup_readonly_private_owner', 'threading', 'socket', 'subprocess', 'types'))))
    lines = ['USE_UI=' + repr(use_ui), 'ERROR_MODULES=(']
    lines.extend('    ' + repr(name) + ',' for name in modules)
    lines.extend((')', 'RESULT_REASONS=('))
    lines.extend('    ' + repr(name) + ',' for name in (UI_REASONS if use_ui else checker.REASONS))
    lines.append(')')
    pins = (RUNNER, WORKER, VALIDATOR) if use_ui else (RUNNER,)
    for tag, pin in zip(('RUNNER', 'WORKER', 'VALIDATOR'), pins):
        lines.append(tag + '_PIN=' + repr(pin[1:]))
        lines.extend((tag + '_ENCODED=(', _short_chunks(checker, inputs[pin[0]]), ')'))
    lines.append('ARTIFACT_ROWS=(')
    for name, path, size, sha in payload:
        lines.append('    (' + repr(name) + ',' + str(size) + ',' + repr(sha) + ',(')
        lines.extend((_short_chunks(checker, inputs[path]), '    )),'))
    lines.append(')')
    raw = ('\n'.join(lines) + '\n' + TARGET_COMMON +
           (TARGET_UI if use_ui else TARGET_SERVICE)).encode('ascii')
    if len(raw) > 2 * 1024 * 1024 or any(len(line) > 256 for line in raw.splitlines()):
        raise ValueError('target_source_budget')
    return raw


def parse_ui_result(raw):
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    lines = derived.splitlines()
    remote = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M)
    rows = [line[7:] for line in lines if line.startswith('RESULT=')]
    if len(remote) != 1 or lines.count('MTA_REMOTE_OK') != 1 or len(rows) != 1:
        raise ValueError('remote_result_unknown')
    value = ast.literal_eval(rows[0])
    if (type(value) is not dict or set(value) != UI_FIELDS or
            any(type(value[key]) is not bool for key in UI_BOOL_FIELDS) or
            any(type(value[key]) is not int or not 0 <= value[key] <= 512 for key in UI_COUNT_FIELDS) or
            type(value['reason']) is not str or value['reason'] not in UI_REASONS):
        raise ValueError('result_fields')
    ready = lines.count('MTA_FORMAL_UI_READY')
    if (ready not in (0, 1) or ready == 1 and not (value['ui_ready'] and value['credentials_removed']) or
            value['complete'] and ready != 1):
        raise ValueError('result_fields')
    return int(remote[0]), value


def host_error_code(error):
    if (type(error) is ValueError and len(error.args) == 1 and
            type(error.args[0]) is str and error.args[0] in HOST_ERROR_CODES):
        return error.args[0]
    for cls, name in ((OSError, 'host_OSError'), (SyntaxError, 'host_SyntaxError'),
                      (TypeError, 'host_TypeError'), (KeyError, 'host_KeyError'),
                      (ValueError, 'host_ValueError'), (RuntimeError, 'host_RuntimeError')):
        if isinstance(error, cls):
            return name
    return 'host_Exception'


def _pin_valid(pin):
    return (type(pin) is tuple and len(pin) == 3 and type(pin[0]) is str and
            type(pin[1]) is int and 0 < pin[1] <= 2 * 1024 * 1024 and
            type(pin[2]) is str and re.fullmatch(r'[0-9a-f]{64}', pin[2]) is not None)


def _write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise OSError('short_write')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    parser.add_argument('--ui', action='store_true')
    args = parser.parse_args()
    if args.ui and not args.check_device:
        parser.error('--ui requires --check-device')
    mode = 'ui' if args.ui else 'service' if args.check_device else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    out = BASE / 'results' / ('formal-receive-v1-' + mode + '-' + stamp + '-' + secrets.token_hex(4))
    private = out / 'private-raw'
    private.mkdir(parents=True, exist_ok=False)
    inputs, programs, checker, component = {}, {}, None, None
    expected_paths = None
    label = 'formal-receive-v1-' + mode
    report = dict(
        schema='p011-formal-receive-v1', mode=mode, passed=False,
        source_check_complete=False, source_graph_crosschecked=False,
        source_preserved=False, source_count=0, payload_role_count=0,
        changed_role_ast_count=0, lifecycle_ast_count=0, envelope_ast_count=0,
        source_runtime_graph_executed=False, old_test_methods=0, old_http_smoke_replayed=False,
        host_error_code=None, device_invoked=False, ui_requested=args.ui,
        host_exit=None, remote_exit=None, remote_status_known=False,
        stdout_bytes=None, stdout_sha256=None, stderr_bytes=None, stderr_sha256=None,
        result_received=False, startup_observation_only=True,
        mta_scan_requested=False, mta_receive_requested=False, mta_send_requested=False,
        receive_admission_requested=False, pending_removed=False, phone_tested=False,
        physical_ui_verified=False, full_network_restore_verified=False,
        whole_system_zero_rf_claimed=False, vendor_binary_replaced=False,
        startup_changed=False, wake_or_timeout_changed=False,
        ui_bundle_staging_requested=False, private_raw_public=False,
        runner_bytes=RUNNER[1], runner_sha256=RUNNER[2],
        worker_bytes=WORKER[1], worker_sha256=WORKER[2],
        validator_bytes=VALIDATOR[1], validator_sha256=VALIDATOR[2])
    try:
        checker, checker_raw = load_checker()
        def retain(path, raw):
            if path in inputs:
                if inputs[path] != raw:
                    raise ValueError('input_shared_changed')
                return
            inputs[path] = raw
            target = out / 'private-inputs' / path
            target.parent.mkdir(parents=True, exist_ok=True)
            _write_new(target, raw)
        retain(CHECKER[0], checker_raw)
        fixed = (MANIFEST, PRIVATE_MANIFEST, RUNNER, WORKER, VALIDATOR, TRANSPORT) + CMDS
        if not all(_pin_valid(pin) for pin in fixed):
            raise ValueError('pins_not_frozen')
        for path, size, sha in fixed:
            retain(path, checker.read_fixed(path, (size, sha)))
        rows = manifest_rows(inputs[MANIFEST[0]])
        private_rows = manifest_rows(inputs[PRIVATE_MANIFEST[0]], private=True)
        payload = rows + HELPERS + private_rows + (WPA, MONITOR)
        if (len(payload) != 73 or len({row[0] for row in payload}) != len(payload) or
                sum(row[2] for row in payload) > 4 * 1024 * 1024):
            raise ValueError('payload_budget')
        for name, path, size, sha in payload:
            retain(path, checker.read_fixed(path, (size, sha)))
        retain(SELF, checker.read_fixed(SELF))
        expected_paths = set(pin[0] for pin in fixed) | {CHECKER[0], SELF} | {row[1] for row in payload}
        if set(inputs) != expected_paths:
            raise ValueError('source_graph')
        inventory = {path: dict(bytes=len(raw), sha256=digest(raw)) for path, raw in inputs.items()}
        _write_new(out / 'private-inputs.json',
                   (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
        ast_count = check_source_graph(checker, inputs, rows, private_rows, payload)
        for use_ui, tag in ((False, 'service'), (True, 'ui')):
            raw = make_source(checker, inputs, payload, use_ui)
            ast.parse(raw.decode('ascii'), feature_version=(3, 5))
            programs[tag] = raw
            _write_new(out / ('private-target-' + tag + '.py'), raw)
            report[tag + '_source_bytes'] = len(raw)
            report[tag + '_source_sha256'] = digest(raw)
        report.update(source_check_complete=True, source_graph_crosschecked=True,
                      source_count=len(inputs), payload_role_count=len(payload),
                      changed_role_ast_count=len(CHANGED_ROLES),
                      lifecycle_ast_count=ast_count - len(CHANGED_ROLES), envelope_ast_count=len(programs))
        if args.check_device:
            # Import only the fixed transport helper; no old checker main/START.
            transport = checker.load_transport(inputs[TRANSPORT[0]])
            adb = transport.Adb(private)
            data = programs['ui' if args.ui else 'service']
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(240);'
                       'exec(sys.stdin.buffer.read(' + str(len(data)) + '))" p011-formal-receive-v1; '
                       'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True
            raw = adb.run(label, ['shell', command], timeout=250, input_data=data)
            remote, component = parse_ui_result(raw) if args.ui else checker.parse_result(raw)
            report.update(remote_status_known=True, remote_exit=remote, result_received=True)
            for key, value in component.items():
                report['component_' + key] = value
    except Exception as error:
        report['host_error_code'] = host_error_code(error)
    finally:
        report['source_count'] = len(inputs)
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
                report[stream + '_bytes'] = len(original)
                report[stream + '_sha256'] = digest(original)
        marker = 'NOT_INVOKED' if not report['device_invoked'] else 'UNKNOWN'
        if stdout_path.exists():
            derived = stdout_path.read_bytes().decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
            found = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M)
            if len(found) == 1:
                report['remote_exit'] = int(found[0])
                report['remote_status_known'] = True
                marker = found[0]
        _write_new(Path(str(prefix) + '.remote-exit'), (marker + '\n').encode('ascii'))
        try:
            report['source_preserved'] = (
                checker is not None and expected_paths is not None and set(inputs) == expected_paths and
                all(checker.read_fixed(path) == raw and (out / 'private-inputs' / path).read_bytes() == raw
                    for path, raw in inputs.items()) and
                all((out / ('private-target-' + tag + '.py')).read_bytes() == raw
                    for tag, raw in programs.items()) and len(programs) == 2)
        except (OSError, ValueError):
            report['source_preserved'] = False
    source_ok = (report['host_error_code'] is None and report['source_check_complete'] and
                 report['source_graph_crosschecked'] and report['source_preserved'])
    if not args.check_device:
        report['passed'] = source_ok and not report['device_invoked']
    elif (source_ok and report['host_exit'] == 0 and report['stderr_bytes'] == 0 and
          report['remote_status_known'] and report['remote_exit'] == 0 and type(component) is dict):
        if args.ui:
            report['passed'] = (
                all(component[key] is True for key in UI_SUCCESS) and
                component['resource_pending'] is False and component['radio_admission'] is False and
                component['physical_ui_verified'] is False and component['reason'] == 'ui_finished')
        else:
            service = tuple(key for key in checker.SERVICE if key != 'http_verified')
            report['passed'] = (
                all(component[key] is True for key in checker.COMMON + service + ('complete',)) and
                component['resource_pending'] is False and component['staging_pending'] is False and
                component['http_verified'] is False and component['http_request_count'] == 0 and
                component['client_socket_count'] == 0 and component['reason'] == 'complete')
    # Never publish raw traces, inventories, tokens, paths from exceptions or user data.
    if any(type(value) not in (type(None), bool, int, str) for value in report.values()):
        raise ValueError('result_fields')
    public = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (
        b'Fixed formal-receive-v1 integration only. Default HOST SOURCE mode byte-checks the pinned '
        b'33 ordinary roles, 35 private roles, three helpers, WPA and one receive monitor (73 payload '
        b'rows), then checks only six changed-role ASTs, runner/worker ASTs, cross-pin literals and two '
        b'new short-line envelopes. It does not execute a synthetic platform graph, old tests, old '
        b'HTTP smoke, old Qt acceptance or any START script. Explicit --check-device stages the fixed '
        b'new graph through its original exclusive FD-ledger process and invokes its fresh original '
        b'Owner startup/close; the focused service makes zero client HTTP smoke requests, so '
        b'http_verified=False and request/client counts zero are intentional, not a failed test. '
        b'Explicit --check-device --ui uses the separately installed immutable copied-vendor UI and '
        b'original endpoint/token handoff, guardian, credential-inode withdrawal, original same-worker '
        b'Owner.close, exact candidate exit and independent stock restoration. It does not stage UI '
        b'assets, touch original Z03/startup, wake the screen or change auto-sleep. The monitor is a '
        b'private byte-verified held-FD extra, not a new Boot canonical role. Startup observation and '
        b'passive-monitor integration are not receive admission. No receive/scan/send/RF request, old '
        b'pending-record handling, phone acceptance or full-network restoration is granted or claimed. '
        b'Copied vendor initialization is not a whole-system zero-RF proof. UI READY/HTTP observations '
        b'are runtime facts only, not physical visibility, touch, layout or real file-receive acceptance. '
        b'Original stdout/stderr, host exit, remote exit, source snapshots, assembled programs and '
        b'bounded private error details remain local, outside this two-member scalar/fixed-text ZIP. '
        b'Host timeout250/remote alarm240; timeout/missing result never signs cleanup, never kills an '
        b'unknown worker and never clears a prior pending record. A PASS describes only its mode.\n')
    _write_new(out / 'result.json', public)
    _write_new(out / 'README.txt', readme)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public)
        bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(archive) as bundle:
        if (bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None or
                bundle.read('result.json') != public or bundle.read('README.txt') != readme):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out),
                         result_zip=str(archive), zip_sha256=digest(archive.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
