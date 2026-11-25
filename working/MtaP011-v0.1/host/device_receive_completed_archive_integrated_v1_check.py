"""SOURCE-only fixed completed receive archive integration.

Default execution is PC SOURCE assembly only: no graph runtime or device IO.
The independent fixed service has archive policy False by default. Only explicit
--check-device --archive-completed-receives selects the fixed trusted True recipe;
it issues no receive/scan/send action. Old CLIENT directories are never indexed
or moved. A future successful original Factory run can be archived only by its
actual Owner.close consumer after original Session/finalizers and restorations.
The old draft/model evidence is preserved and does not validate this new chain.
No UI/FileCenter worker is assembled here; that migration remains separate.
Raw payload <=4MiB, generated ASCII source <=2MiB, lines <=256 stay unchanged.
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
SELF = 'host/device_receive_completed_archive_integrated_v1_check.py'
CHECKER = ('host/device_receive_startup_readonly_v4_check.py', 27003,
           '4ed9c5eb9403f81d967cce91bf21d71e2230d82e49e7d8dfb1d178a353311cbf')
MANIFEST = ('candidate/receive-completed-archive-v1/integrated/manifests/definitions.json', 8168, 'a110b56ea929c7aca2dab71463c15682d629cec9b7f265fda349e727c0485dce')
PRIVATE_MANIFEST = ('candidate/receive-completed-archive-v1/integrated/manifests/private-source.json', 8154, 'f21e7b935f27e77b5fce6a764a705010cb4c32fd9e0360977f2b6125b00a1d86')
PREVIOUS_PRIVATE_SHA = '1da411676f7e368cd188bb8789564aeed8dbaa780f71e7ec859e6f30f0dcc483'
RUNNER = ('candidate/receive-completed-archive-v1/integrated/runtime/mta_formal_receive_session.py', 80671, 'dab38234422d0ff41407c46dbaecc7385d05ef06932610eb65f4dce49fd7653b')
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
CMDS = (('candidate/receive-completed-archive-v1/integrated/HOST_SOURCE.cmd', 287,
          '95595dc35863ef3fb9617010730b5e7c5712e5d1ab4a11c7e40b869c9079ea3d'),)
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
    'mta_client_executor',
    'p011_json',
    'mta_protocol',
    'mta_storage',
    'mta_files',
    'mta_crypto',
    'mta_transfer_session',
    'mta_dhcp',
    'mta_dhcp_server',
    'mta_scoped_sockets',
    'mta_transport',
    'mta_sender',
    'mta_send_worker',
    'mta_scan_handoff',
    'mta_wifi',
    'minhttp',
    'mta_client_control_frame',
    'mta_client_connect_handoff',
    'mta_client_tmp_alias',
    'mta_client_startup_readonly',
    'mta_client_receive_factory',
    'mta_client_state_bridge',
    'mta_go_deployment',
    'mta_send_preparation',
    'mta_go_readonly_parent',
    'mta_go_send_publication',
    'mta_go_send_bridge',
    'mta_go_readonly_terminal_parent',
    'mta_receive_radio_baseline',
    'mta_receive_network',
    'mta_receive_barrier',
    'mta_receive_trial',
    'mta_receive_completed_archive',
    'mta_service',
    'mta_client_receive_boot',
    'mta_client_service_owner',
)
PRIVATE_MODULE_NAMES = (
    'p011_json',
    'mta_ip',
    'mta_client_tmp_alias',
    'mta_p2p_client_init',
    'mta_client_resource_budget',
    'mta_client_proc',
    'mta_client_caps',
    'mta_client_caps_transport',
    'mta_client_baseline',
    'mta_client_journal_codec',
    'mta_client_coordination',
    'mta_client_files',
    'mta_client_pending',
    'mta_client_store',
    'mta_client_process_owner',
    'mta_client_launch_registration',
    'mta_client_two_phase_lease',
    'mta_p2p_client_ctrl',
    'mta_client_wpa_status',
    'mta_protocol',
    'mta_client_control_frame',
    'mta_client_kernel_proof',
    'mta_client_connection',
    'mta_client_linux_provider',
    'mta_client_executor',
    'mta_dhcp',
    'mta_dhcp_client_core',
    'mta_dhcp_client',
    'mta_client_dora',
    'mta_client_dynamic_ip',
    'mta_client_peer',
    'mta_scoped_sockets',
    'mta_storage',
    'mta_transport',
    'mta_client_transfer',
)
CHANGED_ROLES = ('mta_client_executor', 'mta_client_receive_factory', 'mta_client_state_bridge', 'mta_client_receive_boot', 'mta_client_service_owner', 'mta_receive_completed_archive')
CHANGED_SOURCE_PATHS = {
    'mta_client_executor': 'candidate/receive-completed-archive-v1/integrated/runtime/mta_client_executor.py',
    'mta_client_receive_factory': 'candidate/receive-completed-archive-v1/integrated/runtime/mta_client_receive_factory.py',
    'mta_client_state_bridge': 'candidate/receive-completed-archive-v1/integrated/runtime/mta_client_state_bridge.py',
    'mta_client_receive_boot': 'candidate/receive-completed-archive-v1/integrated/runtime/mta_client_receive_boot.py',
    'mta_client_service_owner': 'candidate/receive-completed-archive-v1/integrated/runtime/mta_client_service_owner.py',
    'mta_receive_completed_archive': 'candidate/receive-completed-archive-v1/runtime/mta_receive_completed_archive.py',
}
STATE_ALIAS = '/tmp/p011-mta-receive-completed-archive-v1'
STATE_ROOT = '/var/volatile/tmp/p011-mta-receive-completed-archive-v1'
TRIAL_BOOL_FIELDS = ('requested', 'available', 'claimed', 'session_attached', 'revoked',
                    'expired', 'startup_verified', 'probe_verified', 'radio_known',
                    'barrier_clear', 'network_spec_verified', 'restoration_verified', 'phone_verified')
TRIAL_FIELDS = frozenset(TRIAL_BOOL_FIELDS + ('claim_count', 'reason'))
TRIAL_REASONS = ('not_requested', 'ready', 'claimed', 'revoked', 'expired',
    'owner_context', 'source_changed', 'startup_unknown', 'probe_unknown',
    'radio_unknown', 'radio_unavailable', 'radio_busy', 'network_spec_unknown',
    'barrier_unknown', 'state_not_idle', 'claim_changed', 'already_claimed',
    'session_unknown', 'owner_stopped', 'owner_closed', 'cancelled',
    'state_closing', 'operation_failed', 'session_failed',
    'not_started', 'clear', 'wrong_worker', 'deadline', 'unsupported_platform',
    'unsafe_anchor', 'anchor_changed', 'alias_changed', 'pending_exists',
    'pending_symlink', 'client_root_missing', 'client_history',
    'inventory_unknown', 'descriptor_unknown', 'io_error', 'close_unknown', 'already_attempted')

ARCHIVE_BOOL_FIELDS = ('requested', 'attempted', 'archived', 'rename_called',
    'rename_outcome_known', 'archive_outcome_unknown', 'resources_closed',
    'native_restore_grant', 'receive_admission')
ARCHIVE_FIELDS = frozenset(ARCHIVE_BOOL_FIELDS + ('reason', 'historical_entries_examined'))
ARCHIVE_REASONS = ('not_attempted', 'archived', 'not_requested', 'source_changed',
    'owner_changed', 'receive_not_completed', 'factory_unknown', 'parent_unknown',
    'terminal_unknown', 'journal_unknown', 'marker_present', 'unsafe_path',
    'path_changed', 'unsupported_platform', 'lock_busy', 'lock_unknown',
    'destination_exists', 'deadline', 'io_error', 'rename_failed',
    'rename_unknown', 'close_unknown')
HOST_ERROR_CODES = ('checker_ancestor', 'checker_link', 'checker_file',
    'checker_identity', 'checker_changed', 'checker_pin', 'checker_base',
    'fixed_path', 'fixed_ancestor', 'fixed_link', 'fixed_file', 'fixed_identity',
    'fixed_changed', 'fixed_pin', 'pins_not_frozen', 'input_shared_changed',
    'manifest_schema', 'manifest_row', 'payload_budget', 'source_assignment',
    'source_literal', 'source_graph', 'target_source_budget', 'transport_identity',
    'remote_result_unknown', 'result_fields', 'zip_readback')

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
    # Keep the bootstrap file/pin unchanged. Only this new private helper realm
    # has the exact new runner result schema; no old checker main is executed.
    value.BOOL_FIELDS = value.BOOL_FIELDS + ('interactive_window_requested',)
    value.FIELDS = frozenset(value.BOOL_FIELDS + value.COUNT_FIELDS + ('reason',))
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
        expected_changed_path = CHANGED_SOURCE_PATHS.get(name)
        if not private and expected_changed_path is not None and row['path'] != expected_changed_path:
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
        if isinstance(node, ast.Constant) and type(node.value) in (str, int, float, bool, type(None)):
            return node.value
        if isinstance(node, ast.Tuple):
            return tuple(literal(value) for value in node.elts)
        if isinstance(node, ast.List):
            return [literal(value) for value in node.elts]
        if isinstance(node, ast.Name) and node.id in bindings:
            return bindings[node.id]
        raise ValueError('source_literal')
    return literal(rows[0])




def _false_defaults(tree, name, expected):
    fn = next((node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
               and node.name == name), None)
    if fn is None:
        return False
    values = dict(zip([node.arg for node in fn.args.args][-len(fn.args.defaults):], fn.args.defaults))
    return all(key in values and isinstance(values[key], ast.Constant)
               and values[key].value is False for key in expected)


def check_source_graph(checker, inputs, rows, private_rows, payload):
    ordinary = {name: (path, size, sha) for name, path, size, sha in rows}
    trees = {name: ast.parse(inputs[ordinary[name][0]].decode('utf-8'), feature_version=(3, 5))
             for name in CHANGED_ROLES}
    runner = ast.parse(inputs[RUNNER[0]].decode('utf-8'), feature_version=(3, 5))
    factory, boot = trees['mta_client_receive_factory'], trees['mta_client_receive_boot']
    owner, executor = trees['mta_client_service_owner'], trees['mta_client_executor']
    role_pins = tuple((name, size, sha) for name, path, size, sha in rows)
    private_pins = tuple((name.split('/', 1)[1], size, sha) for name, path, size, sha in private_rows)
    f_sha = ordinary['mta_client_executor'][2]
    source_pins = role_pins[:-2]
    boot_source = inputs[ordinary['mta_client_receive_boot'][0]].decode('utf-8')
    if "SOURCE_PINS[0] != ('mta_client_executor', " + str(source_pins[0][1]) + ", F37_SHA)" not in boot_source:
        raise ValueError('source_graph')
    cls = next((n for n in owner.body if isinstance(n, ast.ClassDef)
                and n.name == 'FixedStateServiceOwner'), None)
    runner_cls = next((n for n in runner.body if isinstance(n, ast.ClassDef)
                       and n.name == 'FixedSession'), None)
    checks = (
        len(role_pins) == 36 and len(source_pins) == 34 and len(private_pins) == 35,
        _assignment(runner, 'ROLE_PINS') == role_pins,
        _assignment(runner, 'PRIVATE_PINS') == private_pins,
        _assignment(runner, 'HELPER_PINS') == tuple((n, z, h) for n, p, z, h in HELPERS),
        _assignment(runner, 'WPA_PIN') == (WPA[0], WPA[2], WPA[3]),
        _assignment(runner, 'MONITOR_PIN') == (MONITOR[0], MONITOR[2], MONITOR[3]),
        _assignment(boot, 'SOURCE_PINS', {'F37_SHA': f_sha}) == source_pins,
        _assignment(factory, 'SOURCE_PINS', {'F_SHA': f_sha}) == private_pins,
        _assignment(boot, 'F37_SHA') == f_sha,
        _assignment(factory, 'F_SHA') == f_sha,
        _assignment(boot, 'CLIENT_MANIFEST_SHA') == PRIVATE_MANIFEST[2],
        _assignment(factory, 'SOURCE_MANIFEST_SHA') == PRIVATE_MANIFEST[2],
        _assignment(trees['mta_client_state_bridge'], 'PARENT_SOURCE_SHA') == f_sha,
        _assignment(owner, 'BOOT_PIN') == ordinary['mta_client_receive_boot'][1:],
        _assignment(owner, 'BOOT_MODULES') == tuple(row[0] for row in source_pins),
        _assignment(owner, 'HELPER_PINS') == tuple((r[2], r[3]) for r in HELPERS[:2]),
        _assignment(owner, 'CONNMAN_PIN') == HELPERS[2][2:],
        _assignment(owner, 'BOOT_SCHEMA') == 'sender-state-boot-v98-source',
        _assignment(boot, 'SOURCE_SCHEMA') == 'sender-state-boot-v98-source',
        _assignment(owner, 'STARTUP_READONLY_SCHEMA') == 'receive-startup-readonly-v1',
        _assignment(factory, 'STARTUP_READONLY_SCHEMA') == 'receive-startup-readonly-v1',
        _assignment(executor, 'ROOT') == '/tmp/p011-mta-client-rfinit',
        _assignment(executor, 'PHYSICAL_ROOT') == '/var/volatile/tmp/p011-mta-client-rfinit',
        _assignment(trees['mta_receive_completed_archive'], 'OWNER_MODULE') == 'startup_readonly_private_owner',
        cls is not None and _false_defaults(cls, '__init__', ('receive_trial_requested', 'archive_completed_receives')),
        runner_cls is not None and _false_defaults(runner_cls, '__init__', ('receive_trial_requested', 'archive_completed_receives')),
        _false_defaults(runner, 'run_fixed', ('receive_trial_requested', 'archive_completed_receives')),
        tuple(_assignment(runner, 'BOOL_FIELDS')) == tuple(checker.BOOL_FIELDS),
        tuple(_assignment(runner, 'COUNT_FIELDS')) == tuple(checker.COUNT_FIELDS),
        tuple(_assignment(runner, 'REASONS')) == tuple(checker.REASONS),
    )
    if not all(checks):
        raise ValueError('source_graph')
    for tree, logical, physical in ((runner, 'STATE_ALIAS', 'STATE_ROOT'),
            (factory, 'ASSET_ROOT', 'ASSET_PHYSICAL_ROOT'), (boot, 'ROOT', 'PHYSICAL_ROOT')):
        if _assignment(tree, logical) != STATE_ALIAS or _assignment(tree, physical) != STATE_ROOT:
            raise ValueError('source_graph')
    if _assignment(owner, 'ROOT') != STATE_ALIAS:
        raise ValueError('source_graph')
    if tuple(row[0] for row in payload) != (
            tuple(row[0] for row in role_pins) + tuple(row[0] for row in HELPERS) +
            tuple('runtime35/' + row[0] for row in private_pins) + (WPA[0], MONITOR[0])):
        raise ValueError('source_graph')
    # This fixed branch is syntax/literal evidence, not a runtime resource proof.
    source = inputs[RUNNER[0]].decode('utf-8')
    if ("if 'startup_readonly_private_owner' in sys.modules: fail('namespace_busy')" not in source or
            "sys.modules[self.owner_module.__name__] = self.owner_module" not in source or
            "self.owner_module = self._owner_module_original = types.ModuleType" not in source or
            source.index("self.loader.load();") >= source.index("sys.modules[self.owner_module.__name__]") or
            source.index("sys.modules[self.owner_module.__name__]") >=
            source.index("exec(self.artifacts['mta_client_service_owner']")):
        raise ValueError('source_graph')
    # Only the one relocated fixed private-asset allowlist changes; CLIENT stays fixed.
    executor_source = inputs[ordinary['mta_client_executor'][0]].decode('utf-8')
    if (STATE_ROOT + '/runtime35' not in executor_source or
            '/var/volatile/tmp/p011-mta-formal-receive-v3/runtime35' in executor_source):
        raise ValueError('source_graph')
    return len(trees) + 1

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
 component=session.run_fixed(artifacts,False,receive_trial_requested=ARCHIVE_POLICY,
                             archive_completed_receives=ARCHIVE_POLICY)
except BaseException as error:
 detail=fixed_error_details((error,))
 if detail:print('ERROR_DETAIL='+repr(detail))
 print('SESSION_ERROR_CODE=service_exception')
 raise SystemExit(2)
retained=session._RETAINED
if retained is not None:
 print('TRIAL_START='+repr(retained.trial_start_facts))
 print('TRIAL_END='+repr(retained.trial_end_facts))
 print('ARCHIVE_END='+repr(retained.archive_end_facts))
if component['complete'] is not True and retained is not None:
 errors=[getattr(retained,'first_error',None)]
 scope=getattr(retained,'startup_scope',None)
 errors.append(getattr(scope,'failure',None))
 collection=getattr(retained,'startup_collection',None)
 errors.append(getattr(collection,'failure',None))
 owner=getattr(retained,'owner',None)
 errors.append(getattr(owner,'receive_trial_failure',None))
 errors.append(getattr(owner,'receive_archive_failure',None))
 errors.extend(getattr(owner,'failures',())[:16])
 trial=getattr(owner,'receive_trial',None)
 errors.append(getattr(trial,'failure',None))
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


def parse_trial_facts(raw):
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    output = {}
    for tag in ('START', 'END'):
        rows = re.findall(r'^TRIAL_' + tag + r'=(.*)$', derived, re.M)
        if len(rows) != 1:
            raise ValueError('remote_result_unknown')
        value = ast.literal_eval(rows[0])
        if (type(value) is not dict or set(value) != TRIAL_FIELDS or
                any(type(value[name]) is not bool for name in TRIAL_BOOL_FIELDS) or
                type(value['claim_count']) is not int or value['claim_count'] not in (0, 1) or
                type(value['reason']) is not str or value['reason'] not in TRIAL_REASONS):
            raise ValueError('result_fields')
        output[tag.lower()] = value
    return output


def parse_archive_facts(raw):
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    rows = re.findall(r'^ARCHIVE_END=(.*)$', derived, re.M)
    if len(rows) != 1:
        raise ValueError('remote_result_unknown')
    value = ast.literal_eval(rows[0])
    if (type(value) is not dict or set(value) != ARCHIVE_FIELDS or
            any(type(value[k]) is not bool for k in ARCHIVE_BOOL_FIELDS) or
            value['reason'] not in ARCHIVE_REASONS or
            type(value['historical_entries_examined']) is not int or value['historical_entries_examined'] != 0 or
            value['native_restore_grant'] is not False or value['receive_admission'] is not False):
        raise ValueError('result_fields')
    return value


def make_source(checker, inputs, payload, archive_policy):
    if type(archive_policy) is not bool:
        raise ValueError('source_graph')
    modules = tuple(sorted(set(MODULE_NAMES + PRIVATE_MODULE_NAMES + (
        'fixed_startup_readonly_diagnostic', 'startup_readonly_private_owner',
        'threading', 'socket', 'subprocess', 'types'))))
    lines = ['USE_UI=False', 'ARCHIVE_POLICY=' + repr(archive_policy), 'ERROR_MODULES=(']
    lines.extend('    ' + repr(name) + ',' for name in modules)
    lines.extend((')', 'RESULT_REASONS=('))
    lines.extend('    ' + repr(name) + ',' for name in
                 tuple(dict.fromkeys(tuple(checker.REASONS) + TRIAL_REASONS + ARCHIVE_REASONS)))
    lines.extend((')', 'RUNNER_PIN=' + repr(RUNNER[1:]), 'RUNNER_ENCODED=(',
                  _short_chunks(checker, inputs[RUNNER[0]]), ')', 'ARTIFACT_ROWS=('))
    for name, path, size, sha in payload:
        lines.extend(('    (' + repr(name) + ',' + str(size) + ',' + repr(sha) + ',(',
                      _short_chunks(checker, inputs[path]), '    )),'))
    lines.append(')')
    raw = ('\n'.join(lines) + '\n' + TARGET_COMMON + TARGET_SERVICE).encode('ascii')
    if len(raw) > 2 * 1024 * 1024 or any(len(line) > 256 for line in raw.splitlines()):
        raise ValueError('target_source_budget')
    return raw


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
    parser.add_argument('--archive-completed-receives', action='store_true')
    args = parser.parse_args()
    if args.archive_completed_receives and not args.check_device:
        parser.error('--archive-completed-receives requires --check-device')
    mode = 'service' if args.check_device else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    label = 'receive-completed-archive-integrated-v1-' + mode
    out = BASE / 'results' / (label + '-' + stamp + '-' + secrets.token_hex(4))
    private = out / 'private-raw'
    private.mkdir(parents=True, exist_ok=False)
    inputs, programs, checker, component, trial_facts, archive_facts = {}, {}, None, None, None, None
    expected_paths = None
    report = dict(schema='p011-receive-completed-archive-integrated-v1', mode=mode, passed=False,
        source_check_complete=False, source_graph_crosschecked=False, source_preserved=False,
        source_count=0, payload_role_count=0, payload_raw_bytes=0,
        changed_role_ast_count=0, lifecycle_ast_count=0, envelope_ast_count=0,
        source_runtime_graph_executed=False, old_test_methods=0, old_http_smoke_replayed=False,
        production_archive_consumer_tested=False, administrative_io_model_replayed=False,
        host_error_code=None, device_invoked=False, host_exit=None, remote_exit=None,
        remote_status_known=False, stdout_bytes=None, stdout_sha256=None,
        stderr_bytes=None, stderr_sha256=None, result_received=False,
        archive_policy_requested=args.archive_completed_receives,
        receive_trial_policy_requested=args.archive_completed_receives,
        auto_receive_action_issued=False, receive_trial_facts_received=False,
        receive_trial_refusal_verified=False, archive_facts_received=False,
        archive_invoked=False, archived=False, archive_outcome_unknown=False,
        archive_resources_closed=False, archive_reason='not_attempted',
        old_client_history_examined=False, historical_entries_examined=0,
        native_restore_grant=False, receive_admission=False, phone_tested=False,
        full_network_restore_verified=False, physical_ui_verified=False,
        ui_worker_migrated=False, filecenter_worker_migrated=False,
        pending_removed=False, vendor_binary_replaced=False, startup_changed=False,
        source_cap_bytes=2097152, payload_cap_bytes=4194304, line_cap_bytes=256,
        service_remote_alarm_seconds=240, service_host_timeout_seconds=250,
        runner_bytes=RUNNER[1], runner_sha256=RUNNER[2])
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
        fixed = (MANIFEST, PRIVATE_MANIFEST, RUNNER, TRANSPORT) + CMDS
        if not all(_pin_valid(pin) for pin in fixed):
            raise ValueError('pins_not_frozen')
        for path, size, sha in fixed:
            retain(path, checker.read_fixed(path, (size, sha)))
        rows = manifest_rows(inputs[MANIFEST[0]])
        private_rows = manifest_rows(inputs[PRIVATE_MANIFEST[0]], private=True)
        payload = rows + HELPERS + private_rows + (WPA, MONITOR)
        if (len(payload) != 76 or len({r[0] for r in payload}) != len(payload) or
                sum(r[2] for r in payload) > 4 * 1024 * 1024):
            raise ValueError('payload_budget')
        report['payload_raw_bytes'] = sum(r[2] for r in payload)
        for name, path, size, sha in payload:
            retain(path, checker.read_fixed(path, (size, sha)))
        retain(SELF, checker.read_fixed(SELF))
        expected_paths = set(pin[0] for pin in fixed) | {CHECKER[0], SELF} | {r[1] for r in payload}
        if set(inputs) != expected_paths:
            raise ValueError('source_graph')
        inventory = {p: dict(bytes=len(r), sha256=digest(r)) for p, r in inputs.items()}
        _write_new(out / 'private-inputs.json',
                   (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
        ast_count = check_source_graph(checker, inputs, rows, private_rows, payload)
        for policy, tag in ((False, 'default-service'), (True, 'enabled-service')):
            raw = make_source(checker, inputs, payload, policy)
            ast.parse(raw.decode('ascii'), feature_version=(3, 5))
            programs[tag] = raw
            _write_new(out / ('private-target-' + tag + '.py'), raw)
            report[tag.replace('-', '_') + '_source_bytes'] = len(raw)
            report[tag.replace('-', '_') + '_source_sha256'] = digest(raw)
        report.update(source_check_complete=True, source_graph_crosschecked=True,
            source_count=len(inputs), payload_role_count=len(payload),
            changed_role_ast_count=len(CHANGED_ROLES), lifecycle_ast_count=ast_count-len(CHANGED_ROLES),
            envelope_ast_count=len(programs))
        if args.check_device:
            transport = checker.load_transport(inputs[TRANSPORT[0]])
            adb = transport.Adb(private)
            data = programs['enabled-service' if args.archive_completed_receives else 'default-service']
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(240);'
                       'exec(sys.stdin.buffer.read(' + str(len(data)) + '))" p011-receive-completed-archive-v1; '
                       'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True
            raw = adb.run(label, ['shell', command], timeout=250, input_data=data)
            remote, component = checker.parse_result(raw)
            report.update(remote_status_known=True, remote_exit=remote, result_received=True)
            for key, value in component.items():
                report['component_' + key] = value
            trial_facts, archive_facts = parse_trial_facts(raw), parse_archive_facts(raw)
            report['receive_trial_facts_received'] = report['archive_facts_received'] = True
            for tag, values in trial_facts.items():
                for key, value in values.items():
                    report['trial_' + tag + '_' + key] = value
            report.update(archive_invoked=archive_facts['attempted'],
                archived=archive_facts['archived'], archive_outcome_unknown=archive_facts['archive_outcome_unknown'],
                archive_resources_closed=archive_facts['resources_closed'], archive_reason=archive_facts['reason'])
    except Exception as error:
        report['host_error_code'] = host_error_code(error)
    finally:
        report['source_count'] = len(inputs)
        prefix = private / ('01-' + label)
        host_path = Path(str(prefix) + '.host-exit')
        if host_path.exists():
            text = host_path.read_text(encoding='ascii').strip()
            report['host_exit'] = int(text) if re.fullmatch(r'-?\d+', text) else 'TIMEOUT'
        stdout_path, stderr_path = Path(str(prefix)+'.stdout.raw'), Path(str(prefix)+'.stderr.raw')
        for stream, path in (('stdout', stdout_path), ('stderr', stderr_path)):
            if path.exists():
                original = path.read_bytes()
                report[stream+'_bytes'], report[stream+'_sha256'] = len(original), digest(original)
        marker = 'NOT_INVOKED' if not report['device_invoked'] else 'UNKNOWN'
        if stdout_path.exists():
            derived = stdout_path.read_bytes().decode('utf-8', 'replace').replace('\r\r\n','\n').replace('\r\n','\n')
            found = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M)
            if len(found) == 1:
                report['remote_exit'], report['remote_status_known'], marker = int(found[0]), True, found[0]
        _write_new(Path(str(prefix)+'.remote-exit'), (marker+'\n').encode('ascii'))
        try:
            report['source_preserved'] = (checker is not None and expected_paths is not None and
                set(inputs) == expected_paths and
                all(checker.read_fixed(p) == r and (out/'private-inputs'/p).read_bytes() == r for p,r in inputs.items()) and
                all((out/('private-target-'+tag+'.py')).read_bytes() == r for tag,r in programs.items()) and
                len(programs) == 2)
        except (OSError, ValueError):
            report['source_preserved'] = False
    source_ok = (report['host_error_code'] is None and report['source_check_complete'] and
                 report['source_graph_crosschecked'] and report['source_preserved'])
    if not args.check_device:
        report['passed'] = source_ok and not report['device_invoked']
    elif (source_ok and report['host_exit'] == 0 and report['stderr_bytes'] == 0 and
          report['remote_status_known'] and report['remote_exit'] == 0 and
          type(component) is dict and type(trial_facts) is dict and type(archive_facts) is dict):
        service = tuple(k for k in checker.SERVICE if k != 'http_verified')
        start, end = trial_facts['start'], trial_facts['end']
        # This no-action focused service can prove refusal/closure only.
        report['receive_trial_refusal_verified'] = (
            start['requested'] is args.archive_completed_receives and start['available'] is False and
            start['claimed'] is False and start['claim_count'] == 0 and start['session_attached'] is False and
            end['requested'] is args.archive_completed_receives and end['available'] is False and
            end['revoked'] is True and end['reason'] == 'owner_closed' and
            end['claimed'] is False and end['claim_count'] == 0 and end['session_attached'] is False and
            start['restoration_verified'] is False and end['restoration_verified'] is False and
            start['phone_verified'] is False and end['phone_verified'] is False)
        report['passed'] = (report['receive_trial_refusal_verified'] and
            all(component[k] is True for k in checker.COMMON+service+('complete',)) and
            component['resource_pending'] is False and component['staging_pending'] is False and
            component['http_verified'] is False and component['http_request_count'] == 0 and
            component['client_socket_count'] == 0 and component['interactive_window_requested'] is False and
            component['reason'] == 'complete' and
            archive_facts['requested'] is args.archive_completed_receives and
            archive_facts['attempted'] is False and archive_facts['archived'] is False and
            archive_facts['rename_called'] is False and archive_facts['archive_outcome_unknown'] is False and
            archive_facts['resources_closed'] is True and archive_facts['reason'] == 'not_attempted')
    if any(type(v) not in (type(None), bool, int, str) for v in report.values()):
        raise ValueError('result_fields')
    public = (json.dumps(report, indent=2, sort_keys=True)+'\n').encode('ascii')
    readme = (
        b'Independent completed archive integration SOURCE/service recipe. Default PC SOURCE only. '
        b'36 ordinary roles/34 Boot modules and 35 isolated CLIENT roles are sealed in a new root; '
        b'CLIENT work root and existing history remain unchanged. Fixed private Owner is registered '
        b'only after Boot load and retained on partial exec. Default archive and receive trial policy '
        b'are False; explicit --check-device --archive-completed-receives selects their fixed True recipe. '
        b'No receive/scan/send action or UI is issued. No-action service PASS is original startup/refusal/'
        b'closure and limited stock/pending unchanged evidence, never Native restoration, file receipt '
        b'or phone acceptance. Archive production capture/consumer remains untested by this service. '
        b'Old administrative model tests are not replayed. Actual production receive can archive only '
        b'the same future successful committed/peer-ACK Factory run at original Owner close. Cancelled/'
        b'partial runs and old CLIENT history remain barriers. Trial cannot reset in a live Owner; '
        b'next receive requires a new bounded original worker. UI/FileCenter migration is not assembled. '
        b'Raw4MiB/source2MiB/line256 and all original temporal caps remain fixed. Failed budget stops, '
        b'no cap increase. Raw bytes/source payload/identifiers remain private; public ZIP only has '
        b'this result and fixed README.\n')
    _write_new(out/'result.json', public)
    _write_new(out/'README.txt', readme)
    archive = out/'public-result.zip'
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json',public)
        bundle.writestr('README.txt',readme)
    with zipfile.ZipFile(archive) as bundle:
        if (bundle.namelist()!=['result.json','README.txt'] or bundle.testzip() is not None or
                bundle.read('result.json')!=public or bundle.read('README.txt')!=readme):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'],mode=mode,result_dir=str(out),
        result_zip=str(archive),zip_sha256=digest(archive.read_bytes())),sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
