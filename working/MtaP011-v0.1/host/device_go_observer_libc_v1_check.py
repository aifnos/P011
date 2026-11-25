"""One isolated observer stage or actual readonly Parent; default PC SOURCE.

No Owner/UI/transfer/RF/history action. Explicit modes use the existing fixed
legacy-ADB carrier, never its old main or old SOURCE checks. Device source and
raw bytes stay private; public ZIP has only result.json and README.txt.
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
SELF = 'host/device_go_observer_libc_v1_check.py'
CMD = 'CHECK_MTA_GO_OBSERVER_LIBC_V1.cmd'
ROOT = '/var/volatile/tmp/p011-mta-go-observer-libc-v1'
CATALOG = ('candidate/go-observer-libc-v1/assets/observer-source-catalog.json',
    15861, '8aaadd3f5a32b184bb851b422781ae8038d699d3e9555cb479cd49f4d090648a')
STAGE = ('candidate/go-observer-libc-v1/runtime/formal_observer_stage.py',
    29349, 'c2799754f4d4638a79ec74e5f029550540b3597f1dbab1ddfc4fd077928b206f')
PARENT = ('candidate/go-observer-libc-v1/runtime/mta_go_readonly_parent.py',
    52881, 'a950577490c576698b3186efe87c6a8da773b21128f836d51b5b26a7bb5d45d6')
GENERATOR = ('host/formal_send_filecenter_deploy_v3_source_check.py',
    30450, '9c5f9db7e9373a72378d622eb16c6fed5f1c94abeca8dd723455fa8518eea8d1')
ENVELOPE = ('host/formal_send_stage_bootstrap_source_check.py',
    19997, 'aede2e43410f7f3a78fb715c077e567da84ba47d9dfa9c5d4290e3b8795b60d3')
WRAPPER = ('candidate/formal-send-stage-bootstrap-v1/runtime/formal_send_stage_bootstrap.py',
    13207, 'c304c4abc854425b51b0f8c8bae3c90361fbfcef5413414a107df9e530169f7d')
CARRIER = ('host/device_formal_send_filecenter_stage_carrier_v3_check.py',
    25857, '043844b6be906369ad16b17562030629213a127756adb73c849b7b7b4c10ff0d')
HELPER = ('host/device_formal_send_filecenter_stage_v1_check.py',
    22495, '68cdbacc1f9a33e61fcdbe603b183909092f2a93c4f7dfcd82a92e2e98b4f145')
TRANSPORT = ('host/device_probe.py', 8759,
    'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
STATUS_KEYS = frozenset(('attempted', 'ended', 'local_inventory_closed', 'resource_pending',
    'failed', 'source_definition_count', 'inventory_rows', 'stdout_bytes', 'stderr_bytes',
    'child_reaped', 'report_observed', 'rf_requested', 'restoration_verified',
    'production_admitted', 'source_authenticated_for_state'))
STATUS_COUNTS = frozenset(('source_definition_count', 'inventory_rows', 'stdout_bytes', 'stderr_bytes'))
CHECK_BOOLS = frozenset(('constructor_complete', 'collect_returned', 'close_returned',
    'original_process', 'original_wait', 'stdout_eof', 'stderr_eof', 'reader_original_result',
    'report_type_original', 'report_manifest_original', 'report_source_count_original',
    'timer_released', 'rf_requested', 'owner_started', 'ui_started', 'restoration', 'admission'))
CHECK_KEYS = CHECK_BOOLS | frozenset(('status', 'child_return', 'reason', 'error_kind', 'error_errno'))
ERRORS = frozenset(('input_pin', 'catalog_shape', 'stage_contract', 'source_budget',
    'source_changed', 'stock_baseline', 'stock_changed', 'carrier_result', 'carrier_files',
    'stage_refused', 'parent_result', 'parent_refused', 'remote_status_unknown', 'host_transport'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if not value:
        raise ValueError(code)


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'source_changed')
    need(path.read_bytes() == raw, 'source_changed')


def fixed(inputs, row):
    path, size, digest = row
    raw = (BASE / path).read_bytes()
    need((len(raw), sha(raw)) == (size, digest), 'input_pin')
    inputs[path] = raw
    return raw


def literal(raw, name):
    tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    rows = [node.value for node in tree.body if isinstance(node, ast.Assign) and
        any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    need(len(rows) == 1, 'stage_contract')
    return ast.literal_eval(rows[0])


def module(raw, path, name):
    # Fixed helper definitions only. Their __main__ blocks cannot run here.
    value = types.ModuleType(name)
    value.__file__ = str(BASE / path)
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value


def selected_generator(raw):
    names = {'literal', 'digest', 'encoded_chunks', 'frame', 'make_program',
             'replace_assignment', 'bootstrap_parts', 'bootstrap_program'}
    tree = ast.parse(raw.decode('ascii'))
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    need({node.name for node in selected} == names and len(selected) == len(names), 'stage_contract')
    namespace = dict(ast=ast, base64=base64, hashlib=hashlib, zlib=zlib,
        LINE=96, MAX_PROGRAM=2097152, MAX_WIRE=4194304, MAX_RAW=4194304,
        STAGE=STAGE, PROGRAM_BODY=literal(raw, 'PROGRAM_BODY'))
    # Only the eight byte/AST-envelope helpers execute on PC. No target classes,
    # old main/source_check/graph_contracts/test method execute.
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<fixed-byte-generator>', 'exec'), namespace)
    return namespace


PARENT_BODY = r'''
import base64,hashlib,math,os,signal,sys,time,types,zlib
_parent=None;_complete=False;_error=None;_closed=False;_data=None;_timer_released=False
_module=types.ModuleType('go_observer_libc_parent_private')
_module.__file__='<fixed-inline-observer-libc-parent>'
_source=None;_originals=[]
_started=time.monotonic();_outer_until=_started+50.0
_handler=signal.getsignal(signal.SIGALRM);_timer=signal.getitimer(signal.ITIMER_REAL)
def require(v):
 if not v:raise ValueError('parent_check_invalid')
def finite_error(e):
 if e is None:return None,None,None
 kind=type(e).__name__
 if not (type(kind)is str and kind.isidentifier() and len(kind)<=64):kind='UnknownError'
 reason=None
 if _source is not None and type(e)is getattr(_module,'ReadonlyParentError',None) and len(e.args)==1:
  if type(e.args[0])is str and e.args[0]in REASONS:reason=e.args[0]
 number=getattr(e,'errno',None)
 if type(number)is not int or not 1<=number<=4095:number=None
 return kind,reason,number
try:
 require(_handler==signal.SIG_DFL and _timer==(0.0,0.0))
 signal.setitimer(signal.ITIMER_REAL,_outer_until-time.monotonic(),0.0)
 require(sys.stdin.buffer.read(len(TRAILER))==TRAILER and sys.stdin.buffer.read(1)==b'')
 decoder=zlib.decompressobj()
 _source=decoder.decompress(base64.b64decode(PARENT_B64,validate=True),PARENT_PIN[0]+1)
 require(len(_source)==PARENT_PIN[0] and decoder.eof and not decoder.unused_data and
  not decoder.unconsumed_tail and hashlib.sha256(_source).hexdigest()==PARENT_PIN[1])
 _originals.append((_module,_module.__dict__,_source))
 exec(compile(_source,_module.__file__,'exec'),_module.__dict__)
 _parent=object.__new__(_module.ReadonlyDataParent);_originals.append(_parent)
 _cap=time.monotonic()+40.0
 _module.ReadonlyDataParent.__init__(_parent,TASK,1,1,_cap,_cap);_complete=True
 _data=_module.ReadonlyDataParent.collect(_parent)
except BaseException as error:
 _error=error
finally:
 if _complete:
  try:_closed=_module.ReadonlyDataParent.close(_parent)is True
  except BaseException as close_error:
   if _error is None:_error=close_error
 status=None;process_original=False;wait_original=False;out_eof=False;err_eof=False;returned=None
 reader_original=False;report_type=False;manifest_original=False;source_count_original=False
 if _complete:
  try:
   status=_module.ReadonlyDataParent.status(_parent)
   ticket=_parent.process_attempt
   if type(ticket)is dict and ticket is _parent.process_attempt_original:
    process_original=(_parent.process is _parent.process_original and ticket['returned']is True and
     ticket['unknown']is False and _parent.process is not None)
    if process_original:
     returned=ticket['wait_return']
     wait_original=(ticket['wait_called']is True and ticket['waited']is True and ticket['reaped']is True and
      ticket['wait_error']is None and type(ticket['wait_ticket'])is tuple and
      ticket['wait_ticket']is ticket['wait_ticket_original'] and len(ticket['wait_ticket'])==6 and
      ticket['wait_ticket'][0]is _parent.process and ticket['wait_ticket'][1]is _parent.process_pid and
      ticket['wait_ticket'][2]is _parent.process_methods[1] and
      ticket['wait_ticket'][3]is returned and _parent.process.returncode is returned and
      ticket['wait_ticket'][4]is ticket['pipes'][0]['eof_ticket'] and
      ticket['wait_ticket'][5]is ticket['pipes'][1]['eof_ticket'])
     eofs=[]
     for row in ticket['pipes']:
      value=row['eof_ticket']
      eofs.append(row['eof']is True and type(value)is tuple and len(value)==7 and
       value[0]is _parent.process and value[1]is _parent.process_pid and value[2]is row and
       value[3]is row['raw_original'] and value[4]is row['fd_original'] and
       value[5]is row['metadata_original'] and value[6]==b'')
     if len(eofs)==2:out_eof,err_eof=eofs
   if _data is not None:
    reader_original=(_data is _parent.result_original and _data is _parent.result and
     _data is _parent.report and _parent.reader is _parent.reader_original and
     _parent.reader.value is _data and _parent.reader.failure is None and _parent.reader.ended is True)
    report_type=type(_data)is _parent.packet_functions[4]
    manifest_original=_data.source_manifest_sha256==MANIFEST_SHA
    source_count_original=type(_data.source_count)is int and _data.source_count==38
   if (type(returned)is not int or not -255<=returned<=255):returned=None
   # Bounded original child bytes only; no argv/binding/task/nonce/snapshot.
   if (type(_parent.stderr_parts)is list and all(type(b)is bytes for b in _parent.stderr_parts) and
       sum(len(b)for b in _parent.stderr_parts)==_parent.stderr_bytes<=16384):
    print('PARENT_STDERR_HEX='+b''.join(_parent.stderr_parts).hex())
  except BaseException as projection_error:
   if _error is None:_error=projection_error
 if _closed and type(status)is dict and status.get('resource_pending')is False:
  try:
   require(signal.getsignal(signal.SIGALRM)==_handler and signal.getitimer(signal.ITIMER_REAL)[1]==0.0 and
    0.0<signal.getitimer(signal.ITIMER_REAL)[0]<=50.0 and time.monotonic()<_outer_until)
   signal.setitimer(signal.ITIMER_REAL,0.0,0.0)
   _timer_released=signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0)
  except BaseException as timer_error:
   if _error is None:_error=timer_error
 kind,reason,number=finite_error(_error)
 result=dict(constructor_complete=_complete,collect_returned=_data is not None,close_returned=_closed,
  original_process=process_original,original_wait=wait_original,stdout_eof=out_eof,stderr_eof=err_eof,
  reader_original_result=reader_original,report_type_original=report_type,
  report_manifest_original=manifest_original,report_source_count_original=source_count_original,
  timer_released=_timer_released,status=status,child_return=returned,reason=reason,
  error_kind=kind,error_errno=number,rf_requested=False,owner_started=False,ui_started=False,
  restoration=False,admission=False)
 print('PARENT_RESULT='+repr(result))
 if _error is not None or _data is None or not _closed or not _timer_released:raise SystemExit(1)
'''


def parent_payload(raw):
    tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    reasons = tuple(sorted({node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call) and
        isinstance(node.func, ast.Name) and node.func.id == '_fail' and len(node.args) == 1 and
        isinstance(node.args[0], ast.Constant) and type(node.args[0].value) is str}))
    need(reasons and all(re.fullmatch(r'parent_[a-z0-9_]+', v) for v in reasons), 'stage_contract')
    wire = b'MTA_OBSERVER_LIBC_PARENT_V1_END\n'
    encoded = base64.b64encode(zlib.compress(raw)).decode('ascii')
    chunks = '\n'.join(' ' + repr(encoded[i:i + 96]) for i in range(0, len(encoded), 96))
    head = ('PARENT_PIN=' + repr(PARENT[1:]) + '\nPARENT_B64=(\n' + chunks + '\n)\n' +
        'TRAILER=' + repr(wire) + '\nTASK=' + repr(secrets.token_hex(16)) + '\nREASONS=' + repr(reasons) +
        "\nMANIFEST_SHA='8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60'\n")
    # Keep the finite reason table itself below the original short-line cap.
    head = head.replace('REASONS=' + repr(reasons), 'REASONS=(\n' +
        ''.join(' ' + repr(reason) + ',\n' for reason in reasons) + ')')
    program = (head + PARENT_BODY).encode('ascii')
    return program, wire, reasons


def payloads(inputs):
    for row in (CATALOG, STAGE, PARENT, GENERATOR, ENVELOPE, WRAPPER, CARRIER, HELPER, TRANSPORT):
        fixed(inputs, row)
    catalog = json.loads(inputs[CATALOG[0]])
    need(catalog['root'] == ROOT and catalog['alias'] == '/tmp/' + ROOT.rsplit('/', 1)[1] and
        catalog['source_count'] == 41 and catalog['source_bytes'] == 1442508 and
        len(catalog['files']) == 41 and catalog['parent_inline_only']['source'] == PARENT[0] and
        catalog['parent_inline_only']['not_in_asset_files'] is True, 'catalog_shape')
    rows = []
    for item in catalog['files']:
        need(item['target'] == ROOT + '/runtime/' + item['module'] + '.py' and
            item['mode'] == '0400', 'catalog_shape')
        raw = fixed(inputs, (item['source'], item['bytes'], item['sha256']))
        rows.append((('runtime/' + item['module'] + '.py', len(raw), sha(raw), 0o400), raw))
    need(sum(len(raw) for pin, raw in rows) == 1442508 and len(set(pin[0] for pin, raw in rows)) == 41,
        'catalog_shape')
    stage = inputs[STAGE[0]]
    need(literal(stage, 'PROFILE_TOTALS') == (('observer', 41, 1442508),) and
        literal(stage, 'PROFILE_FILES') == (('observer', ROOT, tuple(pin for pin, raw in rows)),) and
        literal(stage, 'SERVICE_PARENTS') == () and literal(stage, 'MAX_SECONDS') == 120.0,
        'stage_contract')
    generator = selected_generator(inputs[GENERATOR[0]])
    inner, wire = generator['make_program']('observer', tuple(rows), stage)
    wrapper = inputs[WRAPPER[0]]
    old = b'len(_DATA_TABLE_ORIGINAL) == 3 and'
    need(wrapper.count(old) == 1, 'stage_contract')
    wrapper = wrapper.replace(old, b'len(_DATA_TABLE_ORIGINAL) == 1 and')
    data, wrapper = generator['bootstrap_parts']([('observer', inner)], [('observer', wire)], wrapper)
    program = generator['bootstrap_program']('observer', data, wrapper, literal(inputs[ENVELOPE[0]], 'ENVELOPE'))
    check_program, check_wire, reasons = parent_payload(inputs[PARENT[0]])
    for value in (program, check_program):
        need(len(value) <= 2097152 and max(map(len, value.splitlines())) <= 256, 'source_budget')
        ast.parse(value.decode('ascii'), feature_version=(3, 5))
    need(len(wire) <= 4194304 and max(map(len, wire.splitlines())) <= 256, 'source_budget')
    return (program, wire), (check_program, check_wire), reasons


def parse_parent(raw, reasons, private):
    need(len(raw) <= 1048576, 'parent_result')
    text = raw.decode('ascii', 'strict').replace('\r\r\n', '\n').replace('\r\n', '\n')
    matches = [line[14:] for line in text.splitlines() if line.startswith('PARENT_RESULT=')]
    need(len(matches) == 1 and len(matches[0]) <= 8192, 'parent_result')
    value = ast.literal_eval(matches[0])
    need(type(value) is dict and set(value) == CHECK_KEYS and
        all(type(value[key]) is bool for key in CHECK_BOOLS) and
        (value['reason'] is None or value['reason'] in reasons) and
        (value['child_return'] is None or type(value['child_return']) is int and -255 <= value['child_return'] <= 255) and
        (value['error_errno'] is None or type(value['error_errno']) is int and 1 <= value['error_errno'] <= 4095) and
        (value['error_kind'] is None or type(value['error_kind']) is str and
         re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,63}', value['error_kind'])), 'parent_result')
    status = value['status']
    need(status is None or type(status) is dict and set(status) == STATUS_KEYS and
        all(type(status[key]) is bool for key in STATUS_KEYS - STATUS_COUNTS) and
        all(type(status[key]) is int and 0 <= status[key] <= 1048576 for key in STATUS_COUNTS), 'parent_result')
    stderr = [line[18:] for line in text.splitlines() if line.startswith('PARENT_STDERR_HEX=')]
    need(len(stderr) <= 1 and all(len(line) <= 32768 and re.fullmatch('[0-9a-f]*', line) for line in stderr),
        'parent_result')
    if stderr:
        write_new(private / 'parent-child-stderr.private.raw', bytes.fromhex(stderr[0]))
    return value


def parent_completed(value):
    required = CHECK_BOOLS - {'rf_requested', 'owner_started', 'ui_started', 'restoration', 'admission'}
    status = value['status']
    return (all(value[key] is True for key in required) and value['child_return'] == 0 and
        value['error_kind'] is None and value['reason'] is None and value['error_errno'] is None and
        all(value[key] is False for key in CHECK_BOOLS - required) and type(status) is dict and
        all(status[key] is True for key in ('attempted', 'ended', 'local_inventory_closed',
            'child_reaped', 'report_observed')) and
        all(status[key] is False for key in ('resource_pending', 'failed', 'rf_requested',
            'restoration_verified', 'production_admitted', 'source_authenticated_for_state')) and
        status['source_definition_count'] == 5 and status['inventory_rows'] == 9 and status['stderr_bytes'] == 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--stage-device', action='store_true', help='Only publish the fixed isolated 41-file root.')
    group.add_argument('--check-device', action='store_true', help='One actual readonly Parent child; requires that root.')
    args = parser.parse_args()
    mode = 'stage' if args.stage_device else 'parent' if args.check_device else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
    out = BASE / 'results' / ('go-observer-libc-v1-' + mode + '-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'
    private.mkdir()
    inputs = {}; helper = carrier = transport = adb = before = after = root = launch = row = leaf = None
    report = dict(kind='go-observer-libc-v1-thin', mode=mode, passed=False, source_complete=False,
        source_preserved=False, input_count=0, stage_invoked=False, parent_invoked=False,
        device_invoked=False, device_execution_unknown=False, stock_identity_ok=None, stock_unchanged=None,
        baseline_before_receipt=None, baseline_after_receipt=None, wifi_connected_before=None,
        wifi_connected_after=None, carrier_create_receipt=None, carrier_launch_receipt=None,
        carrier_after_receipt=None, carrier_resources_closed=False, carrier_files_stable=False,
        push_receipts=[], stage_result=None, bootstrap_result=None, parent_result=None,
        source_programs=[], carrier_shell_limit=4096, program_limit=2097152, wire_limit=4194304,
        target_line_limit=256, observer_files=41, observer_bytes=1442508, parent_inline_only=True,
        stage_inner_seconds=120, stage_outer_seconds=180, parent_active_seconds=30,
        parent_cleanup_seconds=5, parent_task_seconds=40, parent_outer_seconds=50,
        rf_requested=False, owner_started=False, ui_started=False, restoration_verified=False,
        production_admitted=False, pending_handled=False, old_tests_run=0, error_code=None)
    try:
        stage_payload, check_payload, reasons = payloads(inputs)
        inputs[SELF] = (BASE / SELF).read_bytes()
        inputs[CMD] = (BASE / CMD).read_bytes()
        helper = module(inputs[HELPER[0]], HELPER[0], 'observer_libc_helper_private')
        carrier = module(inputs[CARRIER[0]], CARRIER[0], 'observer_libc_carrier_private')
        for label, (program, wire) in (('stage', stage_payload), ('parent', check_payload)):
            write_new(private / (label + '.bootstrap.py'), program)
            write_new(private / (label + '.wire.raw'), wire)
            current_row = ('observer', 41, 1442508, len(program), sha(program), len(wire), sha(wire))
            for phase in ('create', 'launch', 'inspect'):
                # Check actual generated carrier shell length with nine-field integer
                # metadata, not a large payload on PTY stdin. Never execute it on PC.
                sample_meta = (66328, 123456789, 16832, 0, 0, 2, 4096, 1770000000000000000, 1770000000000000000)
                sample_files = tuple((name, (66328, 123456789 + n, 33152, 0, 0, 1,
                    current_row[3 if n == 0 else 5], 1770000000000000000, 1770000000000000000))
                    for n, name in enumerate(('bootstrap.py', 'wire.raw')))
                source = carrier.target_source(phase, 'p011-mta-stage-carrier-v3-' + 'f' * 24,
                    current_row, None if phase == 'create' else sample_meta,
                    sample_files if phase == 'inspect' else None)
                ast.parse(source, feature_version=(3, 5))
                carrier.compressed_command(source)
            report['source_programs'].append(dict(mode=label, bytes=len(program), sha256=sha(program),
                wire_bytes=len(wire), wire_sha256=sha(wire), max_line=max(map(len, program.splitlines()))))
        report['source_complete'] = True
        for path, raw in inputs.items():
            write_new(out / 'private-inputs' / path, raw)
        if mode != 'source':
            transport = helper.load_transport(inputs[TRANSPORT[0]])
            report['device_invoked'] = True
            adb = transport.Adb(private)
            before = carrier.baseline(helper, adb, transport, private, 'before', report)
            need(helper.stock_identity(before, transport.PINS), 'stock_baseline')
            program, wire = stage_payload if mode == 'stage' else check_payload
            row = ('observer', 41, 1442508, len(program), sha(program), len(wire), sha(wire))
            leaf = 'p011-mta-stage-carrier-v3-' + secrets.token_hex(12)
            remote = '/var/volatile/tmp/' + leaf
            write_new(private / 'carrier-root.private', remote.encode('ascii'))
            report['device_execution_unknown'] = True
            receipt, raw, error = carrier.run_target(helper, adb, private, 'carrier-create',
                carrier.target_source('create', leaf, row), 30)
            report['carrier_create_receipt'] = receipt
            root = carrier.carrier_result(raw, 'create')
            write_new(private / 'carrier-create.private.json', (json.dumps(root, sort_keys=True) + '\n').encode('ascii'))
            need(error is None and receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                receipt['remote_status_known'] and receipt['remote_exit'] == 0 and root['carrier_created'] and
                root['resources_closed'] and root['opened_fds'] == root['closed_fds'], 'carrier_result')
            for name, data in (('bootstrap.py', program), ('wire.raw', wire)):
                path = private / 'carrier-inputs' / name
                write_new(path, data)
                label = 'push-' + name.split('.')[0]
                stem = '%02d-%s' % (adb.index + 1, label)
                try:
                    adb.run(label, ['push', str(path), remote + '/' + name], timeout=45)
                finally:
                    receipt, ignored = helper.raw_receipt(private, stem, 'MTA_PUSH_REMOTE_EXIT')
                    report['push_receipts'].append(receipt)
                need(receipt['host_exit'] == 0 and path.read_bytes() == data, 'carrier_files')
            report['stage_invoked'] = mode == 'stage'
            report['parent_invoked'] = mode == 'parent'
            receipt, raw, error = carrier.run_target(helper, adb, private, 'carrier-launch',
                carrier.target_source('launch', leaf, row, root['root_metadata']), 210 if mode == 'stage' else 75)
            report['carrier_launch_receipt'] = receipt
            if receipt['remote_status_known'] and type(receipt['host_exit']) is int:
                report['device_execution_unknown'] = False
            # Save actual remote exit before expecting any component projection.
            if mode == 'parent':
                report['parent_result'] = parse_parent(raw, reasons, private)
            else:
                stage, bootstrap, ignored = helper.parse_results(raw, 'observer')
                report['stage_result'], report['bootstrap_result'] = stage, bootstrap
            launch = carrier.carrier_result(raw, 'launch')
            write_new(private / 'carrier-launch.private.json', (json.dumps(launch, sort_keys=True) + '\n').encode('ascii'))
            report['carrier_resources_closed'] = launch['resources_closed']
            report['carrier_files_stable'] = launch['files_stable']
            need(error is None and receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                receipt['remote_status_known'], 'remote_status_unknown')
            need(receipt['remote_exit'] == 0 and launch['resources_closed'] and launch['files_stable'] and
                launch['stdin_regular_verified'] and launch['stdin_closed'],
                'parent_refused' if mode == 'parent' else 'stage_refused')
            if mode == 'parent':
                need(parent_completed(report['parent_result']), 'parent_refused')
            else:
                need(helper.completed(report['stage_result'], report['bootstrap_result'], row), 'stage_refused')
    except BaseException as error:
        report['error_code'] = (error.args[0] if type(error) is ValueError and len(error.args) == 1 and
            type(error.args[0]) is str and error.args[0] in ERRORS else
            'host_transport' if type(error) is RuntimeError else 'unexpected')
    finally:
        if adb is not None:
            if root is not None and root['carrier_created']:
                try:
                    receipt, raw, error = carrier.run_target(helper, adb, private, 'carrier-after',
                        carrier.target_source('inspect', leaf, row, root['root_metadata'],
                            launch['files'] if launch is not None else None), 30)
                    report['carrier_after_receipt'] = receipt
                    value = carrier.carrier_result(raw, 'inspect')
                    need(error is None and receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                        receipt['remote_status_known'] and receipt['remote_exit'] == 0 and value['resources_closed'] and
                        value['files_stable'] and (launch is None or value['files'] == launch['files']), 'carrier_files')
                except BaseException:
                    if report['error_code'] is None:
                        report['error_code'] = 'carrier_files'
            try:
                after = carrier.baseline(helper, adb, transport, private, 'after', report)
                report['stock_identity_ok'] = before is not None and helper.stock_identity(before, transport.PINS) and \
                    helper.stock_identity(after, transport.PINS)
                report['stock_unchanged'] = before is not None and before['stock'] == after['stock']
                need(report['stock_identity_ok'] and report['stock_unchanged'], 'stock_changed')
            except BaseException:
                if report['error_code'] is None:
                    report['error_code'] = 'stock_baseline'
        inventory = {}; preserved = bool(inputs)
        for path, raw in inputs.items():
            try:
                destination = out / 'private-inputs' / path
                if not destination.exists():
                    write_new(destination, raw)
                inventory[path] = dict(bytes=len(raw), sha256=sha(raw))
                preserved = destination.read_bytes() == raw and (BASE / path).read_bytes() == raw and preserved
            except BaseException:
                preserved = False
        report['source_preserved'], report['input_count'] = preserved, len(inputs)
        write_new(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
    report['passed'] = report['source_complete'] and report['source_preserved'] and report['error_code'] is None
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Default PC SOURCE; explicit --stage-device or --check-device only.\n'
        b'41 pinned observer files in a new isolated 0700 root, 0400 files; EXCL, no overwrite/delete.\n'
        b'Old complete root is read-only verified; partial/conflict remains untouched.\n'
        b'Reused carrier creates two private program/wire files; it and all partial assets are retained.\n'
        b'No large PTY stdin. Shell command limit4096; source2MiB, wire/raw4MiB, line256.\n'
        b'Stage original120/180; readonly Parent original30+5 within fixed40, outer50.\n'
        b'Parent uses fixed read-only capability helpers; no Owner/UI/transfer/RF/history/repair.\n'
        b'Actual source/EOF/wait/result/closure is not Native/restore/transfer admission.\n'
        b'Current unrelated radio_pending is neither read as authority nor changed.\n'
        b'Raw/logs/child stderr/source snapshots stay private; public ZIP exactly result+README.\n')
    write_new(out / 'result.json', result)
    write_new(out / 'README.txt', readme)
    with zipfile.ZipFile(out / 'RESULTS.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result)
        archive.writestr('README.txt', readme)
    with zipfile.ZipFile(out / 'RESULTS.zip') as archive:
        need(archive.namelist() == ['result.json', 'README.txt'] and archive.testzip() is None and
            archive.read('result.json') == result and archive.read('README.txt') == readme, 'source_changed')
    code = 0 if report['passed'] else 1
    write_new(out / 'checker-exit.txt', (str(code) + '\n').encode('ascii'))
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out)), sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
