"""Fixed v2 real service/FileCenter diagnostic; default is PC-only.

Explicit --check-device creates one new private carrier and calls the actual
staged Boot/Owner/State and nine-source FileCenter, then immediately closes the
original envelope. No credentials, business HTTP, UI, audio, scan or transfer.
The fixed parent window is 60s plus 60s cleanup; no renewal or fake restoration.
Normal constructors MAY create their fixed user directories. Raw/source/error
details remain private; the public ZIP contains only finite facts and README.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import types
import zipfile
import zlib


BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_filecenter_service_v2_check.py'
CMD = 'TEST_MTA_FORMAL_SEND_FILECENTER_SERVICE_V2.cmd'
CARRIER = ('host/device_formal_send_filecenter_stage_carrier_v2_check.py', 25857,
           '7291f8d9fba9eb7bedc2397a3b8ef3cd11d6f9ed3a9cf863c7e7c0ecc2269ab5')
CATALOG = ('candidate/formal-send-filecenter-deploy-v1/assets/filecenter-source-manifest.json', 2420,
           'ea6d4faf9870181168893da8e3e40ff7e208e1f542762b0e3754b7b9841e350d')
OUTER = ('candidate/formal-send-filecenter-deploy-v2/runtime/formal_send_session.py', 24059,
         '5408b6d72812a46e84d6937263153420e0791313141919bdba949a3eec248b9e')
BOOT = ('candidate/formal-send-filecenter-deploy-v2/runtime/mta_client_receive_boot.py', 19583,
        '3e5cf08d6622933f50b092bbc8f089782fbdbf136241c96cc9f670aa5f0296fa')
OWNER = ('candidate/formal-send-filecenter-deploy-v2/runtime/mta_client_service_owner.py', 82718,
         '841218511bd263e37725359e01f97cac2f168ffaa050fbb6c29e7f58b4bd5ae5')
WIRE = b'MTA_FIXED_SERVICE_DIAGNOSTIC_V2_UNUSED_STDIN\n'
BOOL_FIELDS = ('source_identity_verified', 'constructor_returned', 'start_called',
    'startup_complete', 'filecenter_create_called', 'filecenter_create_original_returned',
    'filecenter_source_originals_verified', 'filecenter_resources_closed', 'owner_close_called',
    'owner_resources_closed', 'state_resources_closed', 'state_probes_closed', 'mta_http_closed',
    'directory_resources_closed', 'outer_close_called', 'outer_resources_closed',
    'resource_pending', 'timer_installed', 'timer_released', 'timer_unknown',
    'send_trial_requested', 'receive_available', 'send_available', 'credentials_called',
    'business_http_called', 'ui_called', 'audio_called', 'rf_requested', 'full_network_restored',
    'may_create_fixed_user_directories', 'physical_stdin_eof_verified')
COUNT_FIELDS = ('filecenter_sources', 'filecenter_source_bytes', 'outer_source_fds',
    'outer_source_fds_closed', 'ordinary_source_fds', 'ordinary_source_fds_closed',
    'owner_asset_fds', 'owner_asset_fds_closed', 'directory_fds', 'directory_fds_closed',
    'capability_actors', 'capability_actors_closed', 'mta_http_requests', 'mta_http_threads')
SERVICE_FIELDS = frozenset(BOOL_FIELDS + COUNT_FIELDS + ('kind', 'profile', 'window_seconds', 'cleanup_seconds'))
ERROR_CODES = frozenset(('input_pin', 'source_budget', 'source_shape', 'source_changed',
    'stock_baseline', 'stock_changed', 'carrier_result', 'carrier_files', 'service_result',
    'service_refused', 'transport_pin', 'host_transport', 'unexpected'))


# The caller does not supply source, root, deadline, profile or requested flags.
# Ten byte-identical fixed sources are decoded before the actual private outer.
# Carrier fd0 is deliberately NOT consumed and physical EOF is not asserted.
SERVICE_BODY = r'''
import base64,errno,hashlib,os,re,signal,sys,threading,time,types,zlib
need=lambda value: value or (_ for _ in ()).throw(ValueError('fixed_service_invalid'))
primary=None;close_error=None;outer=None;original=None;owner=None;filecenter=None;ctor_returned=False
fixed_methods=None;timer_installed=False;timer_released=False;timer_unknown=True
decoded=[];source_verified=False;filecenter_called=False;closed=False
facts={key:False for key in BOOL_FIELDS}
facts.update({key:0 for key in COUNT_FIELDS})
facts.update(kind='formal-send-filecenter-v2-service-diagnostic',profile='diagnostic',
 window_seconds=60,cleanup_seconds=60,resource_pending=True,timer_unknown=True,
 may_create_fixed_user_directories=True)
def retain(error):
 global primary
 if primary is None:primary=error
def fd_counts(rows):
 need(type(rows)is list)
 return len(rows),sum(row.get('closed')is True and row.get('unknown')is False for row in rows)
def error_detail(error):
 code=getattr(error,'code',None)
 if type(code)is not str or re.match(r'^[a-z][a-z0-9_]{0,63}$',code)is None:code=None
 number=getattr(error,'errno',None)
 if type(number)is not int or not 1<=number<=4095:number=None
 frames=[];tb=error.__traceback__
 for unused in range(32):
  if tb is None:break
  name=tb.tb_frame.f_globals.get('__name__');function=tb.tb_frame.f_code.co_name
  if name in ERROR_MODULES and re.match(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$',function):
   frames.append((name,function,tb.tb_lineno))
  tb=tb.tb_next
 kind=type(error).__name__
 if re.match(r'^[A-Za-z_][A-Za-z0-9_]{0,63}$',kind)is None:kind='UnknownError'
 return dict(kind=kind,code=code,errno=number,frames=tuple(frames))
try:
 need(signal.getsignal(signal.SIGALRM)==signal.SIG_DFL and signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0))
 need(signal.setitimer(signal.ITIMER_REAL,180.0)==(0.0,0.0));timer_installed=True
 need(len(DATA)==10 and sum(row[1]for row in DATA)==115354)
 for name,size,sha,parts in DATA:
  raw=zlib.decompress(base64.b64decode(''.join(parts).encode('ascii'),validate=True))
  need(type(raw)is bytes and len(raw)==size and hashlib.sha256(raw).hexdigest()==sha)
  decoded.append((name,raw))
 source_verified=True
 outer=types.ModuleType('formal_send_filecenter_service_diagnostic_private')
 outer.__file__='<fixed-formal-send-filecenter-v2-envelope>'
 exec(compile(decoded[0][1],outer.__file__,'exec'),outer.__dict__)
 need(outer.BOOT_PIN==BOOT_PIN and outer.OWNER_PIN==OWNER_PIN and outer._RETAINED is None)
 cls=outer.FixedSendSession
 fixed_methods=tuple((name,getattr(cls,name))for name in ('__init__','start','close','_closed'))
 original=cls.__new__(cls);outer._RETAINED=original
 started=time.monotonic();parent_until=float(started+60.0);parent_cleanup_until=parent_until+60.0
 cls.__init__(original,parent_until,parent_cleanup_until,False,'diagnostic');ctor_returned=True
 cls.start(original)
 owner=original.owner;module=original.owner_module
 need(type(module)is types.ModuleType and module is sys.modules.get('mta_client_service_owner'))
 need(type(owner)is module.FixedStateServiceOwner and owner is original.owner_ticket['partial'])
 filecenter_called=True
 filecenter=module.FixedStateServiceOwner.create_filecenter(owner,tuple(decoded[1:]))
 ticket=owner.filecenter_ticket
 need(filecenter is ticket['original'] and ticket is owner._filecenter_ticket_original
      and ticket['create_returned']is True and ticket['sources']==tuple(decoded[1:]))
except BaseException as error:retain(error)
finally:
 if ctor_returned:
  try:
   need(type(original)is outer.FixedSendSession and outer._RETAINED is original and
        all(getattr(outer.FixedSendSession,name)is value for name,value in fixed_methods))
   outer.FixedSendSession.close(original)
  except BaseException as error:
   close_error=error;retain(error)
 try:
  facts['source_identity_verified']=source_verified
  facts['constructor_returned']=ctor_returned;facts['filecenter_create_called']=filecenter_called
  facts['filecenter_sources']=9 if source_verified else 0
  facts['filecenter_source_bytes']=91295 if source_verified else 0
  if ctor_returned:
   facts['start_called']=original.start_called is True
   facts['startup_complete']=original.start_complete is True
   facts['outer_close_called']=original.close_called is True
   facts['outer_resources_closed']=outer.FixedSendSession._closed(original)is True
   facts['outer_source_fds'],facts['outer_source_fds_closed']=fd_counts(original.rows)
   if original.loader_ticket is not None and original.loader_ticket['constructed']is True:
    facts['ordinary_source_fds'],facts['ordinary_source_fds_closed']=fd_counts(original.loader.rows)
   owner=original.owner if original.owner_ticket is not None else None
   if original.owner_ticket is not None and original.owner_ticket['constructed']is True:
    module=original.owner_module;cls=module.FixedStateServiceOwner
    need(type(owner)is cls and owner is original.owner_ticket['partial'])
    facts['owner_close_called']=owner.close_called is True
    facts['owner_resources_closed']=cls._closed(owner)is True
    facts['filecenter_resources_closed']=cls._filecenter_closed(owner)is True
    facts['mta_http_closed']=cls._http_passively_closed(owner)is True
    facts['directory_resources_closed']=owner.directory_close_complete is True and cls._directory_inventory_closed(owner)is True
    facts['owner_asset_fds'],facts['owner_asset_fds_closed']=fd_counts(owner.assets)
    facts['mta_http_requests']=len(owner.requests);facts['mta_http_threads']=len(owner.threads)
    if owner.state_complete:
     state=owner.state
     facts['state_resources_closed']=owner.service_methods['closed'](state)is True
     facts['state_probes_closed']=owner.service.State._probes_closed(state)is True
     facts['capability_actors']=len(state.probe_actors)
     facts['capability_actors_closed']=sum(owner.service._probe_closed(row)is True for row in state.probe_actors)
     facts['send_available']=owner.service.State._go_send_admitted(state)is True
     facts['receive_available']=state.receive_available is True
    for ticket in owner.directory_tickets:
     if ticket['complete']is True:
      rows=ticket['value'].rows
      facts['directory_fds']+=len(rows)
      facts['directory_fds_closed']+=sum(row['closed']is True and row['unknown']is False for row in rows)
    ticket=owner.filecenter_ticket
    if ticket is not None:
     facts['filecenter_create_original_returned']=ticket is owner._filecenter_ticket_original and ticket['create_returned']is True and filecenter is ticket['original']
     facts['filecenter_source_originals_verified']=cls._filecenter_definitions_current(owner)is True
  closed=all(facts[key]is True for key in ('outer_resources_closed','owner_resources_closed',
   'filecenter_resources_closed','state_resources_closed','state_probes_closed',
   'mta_http_closed','directory_resources_closed'))
  facts['resource_pending']=not closed
  if closed:
   current=signal.getitimer(signal.ITIMER_REAL)
   need(timer_installed and 0<current[0]<=180.0 and current[1]==0.0)
   signal.setitimer(signal.ITIMER_REAL,0.0)
   need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0));timer_released=True;timer_unknown=False
 except BaseException as error:retain(error)
 facts['timer_installed']=timer_installed;facts['timer_released']=timer_released;facts['timer_unknown']=timer_unknown
 print('SERVICE_RESULT='+repr(facts))
 if primary is not None:print('SERVICE_ERROR_DETAIL='+repr(error_detail(primary)))
 if close_error is not None and close_error is not primary:print('SERVICE_CLEANUP_ERROR_DETAIL='+repr(error_detail(close_error)))
 if primary is not None:raise primary
 need(closed and facts['filecenter_create_original_returned']and facts['startup_complete'])
'''


def read_fixed(inputs, pin):
    path, size, sha = pin
    raw = (BASE / path).read_bytes()
    inputs[path] = raw
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('input_pin')
    return raw


def load_carrier(inputs):
    raw = read_fixed(inputs, CARRIER)
    module = types.ModuleType('formal_send_service_carrier_helpers_private')
    module.__file__ = str(BASE / CARRIER[0])
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    helper = module.load_local_helper(inputs)
    # Definitions only. Do not call the old main/local_inputs/stage parser.
    read_fixed(inputs, helper.TRANSPORT)
    return module, helper


def make_program(inputs):
    outer = read_fixed(inputs, OUTER)
    boot = read_fixed(inputs, BOOT)
    owner = read_fixed(inputs, OWNER)
    catalog = json.loads(read_fixed(inputs, CATALOG))
    if (catalog.get('source_count') != 9 or catalog.get('source_bytes') != 91295 or
            catalog.get('source_cap') != 131072 or catalog.get('in_protocol_stage_payload') is not False):
        raise ValueError('source_shape')
    rows = [('fixed_outer', outer)]
    for row in catalog['sources']:
        rows.append((row['module'], read_fixed(inputs, (row['source'], row['bytes'], row['sha256']))))
    def assignments(raw, name):
        values = [node.value for node in ast.parse(raw).body if isinstance(node, ast.Assign) and
                  any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        if len(values) != 1:
            raise ValueError('source_shape')
        return ast.literal_eval(values[0])
    if (assignments(outer, 'BOOT_PIN') != BOOT[1:] or assignments(outer, 'OWNER_PIN') != OWNER[1:] or
            tuple((name, len(raw), hashlib.sha256(raw).hexdigest()) for name, raw in rows[1:]) !=
            assignments(owner, 'FILECENTER_PINS')):
        raise ValueError('source_shape')
    modules = tuple(row[0] for row in assignments(boot, 'SOURCE_PINS')) + tuple(row[0] for row in rows[1:])
    header = ['BOOT_PIN='+repr(BOOT[1:]), 'OWNER_PIN='+repr(OWNER[1:]), 'BOOL_FIELDS=(',]
    header.extend(' '+repr(name)+',' for name in BOOL_FIELDS)
    header.extend((')', 'COUNT_FIELDS=('))
    header.extend(' '+repr(name)+',' for name in COUNT_FIELDS)
    header.extend((')', 'ERROR_MODULES=('))
    header.extend(' '+repr(name)+',' for name in modules + ('formal_send_filecenter_service_diagnostic_private',))
    header.extend((')', 'DATA=('))
    for name, raw in rows:
        encoded = base64.b64encode(zlib.compress(raw, 9)).decode('ascii')
        header.append(' ('+repr(name)+','+str(len(raw))+','+repr(hashlib.sha256(raw).hexdigest())+',(')
        header.extend('  '+repr(encoded[index:index+96])+',' for index in range(0, len(encoded), 96))
        header.append('  )),')
    header.append(')')
    source = ('\n'.join(header)+'\n'+SERVICE_BODY).encode('ascii')
    if len(source) > 2097152 or max(map(len, source.splitlines())) > 256:
        raise ValueError('source_budget')
    ast.parse(source, feature_version=(3, 5))
    return source


def target_source(carrier, mode, leaf, row, root=None, files=None):
    if mode not in ('create', 'launch', 'inspect') or re.fullmatch(r'p011-mta-service-carrier-v2-[0-9a-f]{24}', leaf) is None:
        raise ValueError('source_shape')
    body = '\n'.join(line for line in carrier.CARRIER_BODY.splitlines() if not line.lstrip().startswith('#'))+'\n'
    return ('MODE='+repr(mode)+'\nLEAF='+repr(leaf)+'\nFILE_MODES='+repr(carrier.FILE_MODES)+
        '\nBOOTSTRAP_PIN='+repr(row[3:5])+'\nWIRE_PIN='+repr(row[5:7])+
        '\nEXPECTED_ROOT='+repr(root)+'\nEXPECTED_FILES='+repr(files)+'\n'+body)


def service_result(helper, raw):
    lines = helper.normalized(raw).splitlines()
    selected = [line[len('SERVICE_RESULT='):] for line in lines if line.startswith('SERVICE_RESULT=')]
    if len(selected) != 1 or len(selected[0]) > 16384:
        raise ValueError('service_result')
    value = ast.literal_eval(selected[0])
    if (type(value) is not dict or set(value) != SERVICE_FIELDS or
            any(type(value[name]) is not bool for name in BOOL_FIELDS) or
            any(type(value[name]) is not int or not 0 <= value[name] <= 2097152 for name in COUNT_FIELDS) or
            value['kind'] != 'formal-send-filecenter-v2-service-diagnostic' or value['profile'] != 'diagnostic' or
            type(value['window_seconds']) is not int or value['window_seconds'] != 60 or
            type(value['cleanup_seconds']) is not int or value['cleanup_seconds'] != 60):
        raise ValueError('service_result')
    return value


def service_complete(value):
    required = ('source_identity_verified', 'constructor_returned', 'start_called', 'startup_complete',
        'filecenter_create_called', 'filecenter_create_original_returned', 'filecenter_source_originals_verified',
        'filecenter_resources_closed', 'owner_close_called', 'owner_resources_closed', 'state_resources_closed',
        'state_probes_closed', 'mta_http_closed', 'directory_resources_closed', 'outer_close_called',
        'outer_resources_closed', 'timer_installed', 'timer_released', 'may_create_fixed_user_directories')
    forbidden = ('resource_pending', 'timer_unknown', 'send_trial_requested', 'receive_available', 'send_available',
        'credentials_called', 'business_http_called', 'ui_called', 'audio_called', 'rf_requested',
        'full_network_restored', 'physical_stdin_eof_verified')
    pairs = (('outer_source_fds', 'outer_source_fds_closed'), ('ordinary_source_fds', 'ordinary_source_fds_closed'),
        ('owner_asset_fds', 'owner_asset_fds_closed'), ('directory_fds', 'directory_fds_closed'),
        ('capability_actors', 'capability_actors_closed'))
    return (all(value[name] is True for name in required) and all(value[name] is False for name in forbidden) and
        all(value[a] > 0 and value[a] == value[b] for a, b in pairs) and value['filecenter_sources'] == 9 and
        value['filecenter_source_bytes'] == 91295 and value['capability_actors'] == 2 and
        value['mta_http_requests'] == 0 and value['mta_http_threads'] == 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4)
    out = BASE/'results'/('formal-send-filecenter-service-v2-'+stamp)
    out.mkdir(parents=True, exist_ok=False)
    private = out/'private-raw'; private.mkdir()
    inputs = {}; carrier = helper = transport = adb = before = root = launch = None
    report = dict(kind='formal-send-filecenter-v2-service-diagnostic', mode='device' if args.check_device else 'local',
        passed=False, local_inputs_verified=False, source_preserved=False, input_count=0, error_code=None,
        service_invoked=False, service_execution_unknown=False, service_result=None, stock_identity_ok=None,
        stock_unchanged=None, wifi_connected_before=None, wifi_connected_after=None,
        baseline_before_receipt=None, baseline_after_receipt=None, carrier_create_receipt=None,
        carrier_launch_receipt=None, carrier_after_receipt=None, push_receipts=[], carrier_created=False,
        carrier_created_files=0, carrier_files_stable=False, carrier_resources_closed=False,
        may_create_fixed_user_directories=True, credentials_or_ui_or_rf_requested=False,
        guardian_supplied=False, production_or_full_restoration=False, retained_carrier=True)
    try:
        carrier, helper = load_carrier(inputs)
        program = make_program(inputs)
        inputs[SELF] = (BASE/SELF).read_bytes(); inputs[CMD] = (BASE/CMD).read_bytes()
        for path, raw in inputs.items(): helper.write_new(out/'private-inputs'/path, raw)
        helper.write_new(private/'carrier-inputs'/'bootstrap.py', program)
        helper.write_new(private/'carrier-inputs'/'wire.raw', WIRE)
        row = ('service', 0, 0, len(program), helper.digest(program), len(WIRE), helper.digest(WIRE))
        report['program_bytes'], report['program_sha256'] = row[3:5]
        report['wire_bytes'], report['wire_sha256'] = row[5:7]
        report['local_inputs_verified'] = True
        if args.check_device:
            transport = helper.load_transport(inputs[helper.TRANSPORT[0]])
            adb = transport.Adb(private)
            before = carrier.baseline(helper, adb, transport, private, 'before', report)
            report['stock_identity_ok'] = helper.stock_identity(before, transport.PINS)
            helper.need(report['stock_identity_ok'], 'stock_baseline')
            leaf = 'p011-mta-service-carrier-v2-'+secrets.token_hex(12)
            remote_root = '/var/volatile/tmp/'+leaf
            helper.write_new(private/'carrier-root.private', remote_root.encode('ascii'))
            receipt, raw, error = carrier.run_target(helper, adb, private, 'carrier-create',
                target_source(carrier, 'create', leaf, row), 30)
            report['carrier_create_receipt'] = receipt
            root = carrier.carrier_result(raw, 'create')
            report['carrier_created'] = root['carrier_created']
            helper.need(error is None and receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                receipt['remote_status_known'] and receipt['remote_exit'] == 0 and root['carrier_created'] and
                root['resources_closed'], 'carrier_result')
            for name in ('bootstrap.py', 'wire.raw'):
                label = 'push-'+name.split('.')[0]; stem = '%02d-%s' % (adb.index+1, label)
                try: adb.run(label, ['push', str(private/'carrier-inputs'/name), remote_root+'/'+name], timeout=45)
                finally:
                    push_receipt, unused = helper.raw_receipt(private, stem, 'MTA_PUSH_REMOTE_EXIT')
                    report['push_receipts'].append(push_receipt)
                helper.need(push_receipt['host_exit'] == 0, 'carrier_files')
            report['carrier_created_files'] = 2
            report['service_invoked'] = report['service_execution_unknown'] = True
            receipt, raw, error = carrier.run_target(helper, adb, private, 'carrier-launch',
                target_source(carrier, 'launch', leaf, row, root['root_metadata']), 210)
            report['carrier_launch_receipt'] = receipt
            if type(receipt['host_exit']) is int and receipt['remote_status_known']:
                report['service_execution_unknown'] = False
            # Preserve actual service facts even if carrier cleanup was refused.
            report['service_result'] = service_result(helper, raw)
            launch = carrier.carrier_result(raw, 'launch')
            report['carrier_files_stable'] = launch['files_stable']
            report['carrier_resources_closed'] = launch['resources_closed']
            helper.need(error is None and receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                receipt['remote_status_known'] and receipt['remote_exit'] == 0 and launch['resources_closed'] and
                launch['files_stable'] and launch['stdin_regular_verified'] and launch['stdin_closed'] and
                service_complete(report['service_result']), 'service_refused')
    except BaseException as error:
        report['error_code'] = error.args[0] if type(error) is ValueError and len(error.args) == 1 and \
            type(error.args[0]) is str and error.args[0] in ERROR_CODES else (
            'host_transport' if type(error) is RuntimeError else 'unexpected')
    finally:
        if helper is not None and adb is not None:
            if root is not None and report['carrier_created']:
                try:
                    receipt, raw, error = carrier.run_target(helper, adb, private, 'carrier-after',
                        target_source(carrier, 'inspect', leaf, row, root['root_metadata'],
                                      launch['files'] if launch is not None else None), 30)
                    report['carrier_after_receipt'] = receipt
                    value = carrier.carrier_result(raw, 'inspect')
                    helper.need(error is None and receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                        receipt['remote_status_known'] and receipt['remote_exit'] == 0 and value['files_stable'] and
                        value['resources_closed'] and (launch is None or value['files'] == launch['files']), 'carrier_files')
                    if launch is not None: report['carrier_files_stable'] = report['carrier_files_stable'] and value['files_stable']
                except BaseException:
                    report['carrier_files_stable'] = False
                    if report['error_code'] is None: report['error_code'] = 'carrier_files'
            try:
                after = carrier.baseline(helper, adb, transport, private, 'after', report)
                report['stock_identity_ok'] = before is not None and helper.stock_identity(before, transport.PINS) and \
                    helper.stock_identity(after, transport.PINS)
                report['stock_unchanged'] = before is not None and before['stock'] == after['stock']
                helper.need(report['stock_identity_ok'] and report['stock_unchanged'], 'stock_changed')
            except BaseException:
                if report['error_code'] is None: report['error_code'] = 'stock_baseline'
        inventory = {}; preserved = bool(inputs)
        for path, raw in inputs.items():
            try:
                snapshot = out/'private-inputs'/path
                if not snapshot.exists():
                    snapshot.parent.mkdir(parents=True, exist_ok=True)
                    with snapshot.open('xb') as handle: handle.write(raw)
                inventory[path] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                if snapshot.read_bytes() != raw or (BASE/path).read_bytes() != raw: preserved = False
            except BaseException: preserved = False
        report['source_preserved'], report['input_count'] = preserved, len(inputs)
        with (out/'private-inputs.json').open('xb') as handle:
            handle.write((json.dumps(inventory, sort_keys=True, indent=2)+'\n').encode('ascii'))
    report['passed'] = report['local_inputs_verified'] and report['source_preserved'] and report['error_code'] is None
    result = (json.dumps(report, sort_keys=True, indent=2)+'\n').encode('ascii')
    readme = (b'Fixed v2 real service and FileCenter diagnostic. Default is PC-only source construction.\n'
        b'Explicit device mode starts actual staged Boot32/Owner/State, creates original nine-source FileCenter, closes immediately.\n'
        b'Parent60+cleanup60, outer180/HOST210; no wait, renewal, credentials, business HTTP, UI, audio, transfer or scan.\n'
        b'Capability child processes and localhost listeners/threads are real activity, not a zero-process claim.\n'
        b'A fresh EXCL private carrier adds two files. Normal constructors MAY create fixed user directories.\n'
        b'No old asset/root overwrite, removal, chmod, CLIENT/pending handling or retry. Carrier and partial resources are retained.\n'
        b'Unknown/partial/false component closure remains failure; no fake guardian or native/network restoration grant.\n'
        b'Limited stock/process/WiFi before/after is not complete network/radio restoration or phone interoperability.\n'
        b'Carrier fd0 is not consumed by the service; no physical EOF claim. Tokens/endpoints/errors/sources/raw remain private.\n')
    for name, raw in (('result.json', result), ('README.txt', readme)):
        with (out/name).open('xb') as handle: handle.write(raw)
    with zipfile.ZipFile(out/'RESULTS.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result); archive.writestr('README.txt', readme)
    with zipfile.ZipFile(out/'RESULTS.zip') as archive:
        if archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or \
                archive.read('result.json') != result or archive.read('README.txt') != readme:
            raise ValueError('source_changed')
    print(json.dumps(dict(passed=report['passed'], mode=report['mode'], result_dir=str(out)), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
