"""Fixed Receive UI-v1 carrier: SOURCE default; explicit file-only stage or UI smoke.

Only the new ten-file bundle is staged. The genuine Receive worker owns one
600+60 profile and one MTA credential pair; smoke shortens display to launched
+20s, not READY+20s. No sender worker, companion, automatic discovery or phone
action. Fixed carrier/source/wire use exclusive files, never large PTY stdin.
Old helpers supply definitions only; no old main, suite, graph or builder runs.
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
import traceback
import types
import zipfile
import zlib

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_receive_ui_v1_check.py'
CMDS = ('STAGE_MTA_FORMAL_RECEIVE_UI_V1_ASSETS.cmd', 'TEST_MTA_FORMAL_RECEIVE_UI_V1.cmd')
SESSION = '2c3d526c2d034da16e6c4a61'
BUNDLE = 'out/mta-ui-receive-v1-' + SESSION
REMOTE = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
RUNTIME = 'candidate/formal-receive-ui-v1/runtime/'
WORKER = (RUNTIME + 'ui_session.py', 57490,
          'b3ca0e8ca285ece326f089f06a749599daa579debea2d0fc046b404da153fee6')
VALIDATOR = (RUNTIME + 'ui_assets.py', 10447,
             '570400c728e2ddeb3993d571f27fb941a7833b43db8183c9d0e588997ddef33d')
DEFINITIONS = ('host/formal_receive_ui_v1_definitions.py', 10721,
               '9450c13671d0f2c9ff113f1b369ce4a83175aace2834585b74ff3e2f1bd33bc8')
STAGE_MANIFEST = (BUNDLE + '/stage-manifest.json', 2575,
                  '3b67bee55d3daa063396ba0d9044938be181f35f64683fa258fc6f0a526eea73')
NATIVE = ('host/device_formal_ui_assets_v1_check.py', 43171,
          '962d1de014bb7f1be677ed997eaae67c13f88e204d916bb9a8526d0b9a6b0a4c')
UI_CARRIER = ('host/device_formal_send_filecenter_ui_v7_check.py', 28635,
              'b888055f21b21eb60d003e8dd00fde62646ef1dd2628d568146b987689ed2449')
CARRIER = ('host/device_formal_send_filecenter_stage_carrier_v3_check.py', 25857,
           '043844b6be906369ad16b17562030629213a127756adb73c849b7b7b4c10ff0d')
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
STARTUP_BOOLS = ('startup_readonly_called', 'startup_readonly_verified',
 'startup_baseline_collected', 'startup_status_verified', 'startup_resources_closed')
UI_BOOLS = ('complete', 'ui_ready', 'ui_http_observed', 'owner_close_verified',
 'credentials_removed', 'candidate_exited', 'stock_restored', 'guardian_exited',
 'worker_fds_closed', 'radio_admission', 'original_ui_exited', 'physical_ui_verified',
 'resource_pending', 'receive_trial_policy_requested', 'auto_receive_action_issued',
 'receive_trial_initial_observed', 'receive_trial_initial_available',
 'receive_trial_claimed', 'receive_trial_session_attached',
 'receive_trial_terminal_observed', 'receive_trial_terminal_revoked',
 'interactive_window_requested', 'interactive_window_expired', 'interactive_window_bound',
 'smoke_requested', 'smoke_display_finished', 'smoke_idle_observed') + STARTUP_BOOLS
UI_COUNTS = ('startup_status_count', 'startup_proc_reader_count',
             'receive_trial_claim_count', 'smoke_display_seconds')
UI_REASONS = ('reason', 'receive_trial_initial_reason', 'receive_trial_terminal_reason')
UI_FIELDS = frozenset(UI_BOOLS + UI_COUNTS + UI_REASONS)
UI_SUCCESS = tuple(key for key in UI_BOOLS if key not in ('radio_admission',
 'physical_ui_verified', 'resource_pending', 'auto_receive_action_issued',
 'receive_trial_initial_available', 'receive_trial_claimed',
 'receive_trial_session_attached', 'interactive_window_expired'))


def need(value, code):
 if value is not True: raise ValueError(code)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
 path.parent.mkdir(parents=True, exist_ok=True)
 with path.open('xb') as handle: need(handle.write(raw) == len(raw), 'host_write')


def definitions(path, raw, name):
 module = types.ModuleType(name); module.__file__ = str(BASE / path)
 exec(compile(raw, module.__file__, 'exec'), module.__dict__)
 return module


def replace_exact(raw, old, new, count):
 need(raw.count(old) == count, 'native_target_literal_count')
 return raw.replace(old, new)


def asset_helper(helper, validator):
 """Native algorithms unchanged; only fixed inventory/path/pin literals differ."""
 helper.SESSION, helper.BUNDLE, helper.REMOTE = SESSION, BUNDLE, REMOTE
 helper.VALIDATOR = VALIDATOR
 helper.PINS = validator.PINS
 helper.MANIFEST = ('SOURCE.sha256',) + validator.MANIFEST_PIN
 helper.ASSET_PINS = helper.PINS + (helper.MANIFEST,)
 helper.ROOT_NAMES, helper.DEVICE_NAMES = validator.ROOT_NAMES, validator.MTA_NAMES
 target = helper.TARGET
 for old, new, count in (
  ('sum(pin[1] for pin in ASSET_PINS)==4150005',
         'sum(pin[1] for pin in ASSET_PINS)==4151735', 1),
  ("(10489,'e58de146a8274402af0535972b8179f1d7a973320f3437935a29212a962e6507')",
         '(' + str(VALIDATOR[1]) + ',' + repr(VALIDATOR[2]) + ')', 1),
  ("self.directory('device',session['fd'],'private')",
         "self.directory('mta',session['fd'],'private')", 1),
  ("self.new_directory(self.session['fd'],'device')",
         "self.new_directory(self.session['fd'],'mta')", 1),
  ("pin[0][7:]) if pin[0].startswith('device/')",
         "pin[0][4:]) if pin[0].startswith('mta/')", 2),
  ('self.validator.DEVICE_NAMES==DEVICE_NAMES',
         'self.validator.MTA_NAMES==DEVICE_NAMES', 1)):
  target = replace_exact(target, old, new, count)
 helper.TARGET = target
 return helper


def stage_program(helper, inputs):
 """Native original activity/cleanup60+60 under its original outer alarm180."""
 source, wire = helper.make_source(inputs)
 literal = '(\n' + '\n'.join(' ' + repr(source[at:at + 256])
        for at in range(0, len(source), 256)) + '\n)'
 program = ('import signal\nsignal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(180)\n'
  'namespace={"__name__":"__main__"}\nstatus=1\ntry:\n exec(compile(' + literal +
  ',"<fixed-receive-ui-v1-asset-stage>","exec"),namespace)\n'
  'except SystemExit as error:\n status=error.code\n'
  'component=namespace.get("component")\n'
  'closed=(type(component)is dict and component.get("original_fds_closed")is True and '
  'component.get("resource_pending")is False and (component.get("validator_called")is False or '
  'component.get("validator_called")is True and component.get("validator_fds_closed")is True))\n'
  'if closed:signal.setitimer(signal.ITIMER_REAL,0.0)\nraise SystemExit(status)\n')
 return program.encode('ascii'), wire


def ui_program(inputs, payload, runner, carrier):
 """Decode original75 once; only the genuine Receiver worker constructs a profile."""
 lines = ['import base64,hashlib,signal,sys,time,types,zlib',
  'started=time.monotonic();outer_until=started+800.0',
  'signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(20)',
  'def decode(data,size,sha):',
  ' d=zlib.decompressobj();raw=d.decompress(base64.b64decode(data,validate=True),size+1)',
  ' if len(raw)!=size or not d.eof or d.unused_data or d.unconsumed_tail or hashlib.sha256(raw).hexdigest()!=sha:raise ValueError("source_pin")',
  ' return raw', 'sources={}']
 for name, pin in (('worker', WORKER), ('runner', runner), ('assets', VALIDATOR)):
  lines.append('sources[' + repr(name) + ']=decode((\n' + carrier.encoded(inputs[pin[0]]) +
                     '),' + repr(pin[1]) + ',' + repr(pin[2]) + ')')
 lines.append('artifacts=[]')
 for name, path, size, sha in payload:
  lines.append('artifacts.append((' + repr(name) + ',' + str(size) + ',' + repr(sha) +
                     ',decode((\n' + carrier.encoded(inputs[path]) + '),' + str(size) + ',' + repr(sha) + ')))')
 wire = b'P011_FORMAL_RECEIVE_UI_V1_SMOKE_ONLY\n'
 lines += ['wire=sys.stdin.buffer.read(' + str(len(wire)) + ')',
  'if wire!=' + repr(wire) + ':raise ValueError("wire_pin")',
  'remaining=outer_until-time.monotonic()',
  'if not 0<remaining<=800.0:raise ValueError("outer_deadline")',
  'signal.setitimer(signal.ITIMER_REAL,remaining)',
  'worker=types.ModuleType("fixed_formal_receive_ui_v1_worker")',
  'worker.__file__="<fixed-formal-receive-ui-v1-worker>"',
  'exec(compile(sources["worker"],worker.__file__,"exec"),worker.__dict__)',
  'component=worker.run_fixed(sources["runner"],tuple(artifacts),sources["assets"],smoke_only=True)',
  'print("RESULT="+repr(component));print("MTA_REMOTE_OK")',
  'closed=(type(component)is dict and all(component.get(k)is True for k in ("candidate_exited","owner_close_verified","guardian_exited","worker_fds_closed","credentials_removed")) and component.get("resource_pending")is False)',
  'if closed:signal.setitimer(signal.ITIMER_REAL,0.0)',
  'raise SystemExit(0 if component.get("complete")is True else 1)']
 return ('\n'.join(lines) + '\n').encode('ascii'), wire


def component(raw, helper, ui):
 text = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
 rows = [line[7:] for line in text.splitlines() if line.startswith('RESULT=')]
 need(len(rows) == 1 and len(rows[0]) <= 16384 and
         text.splitlines().count('MTA_REMOTE_OK') == 1, 'component_missing')
 value = ast.literal_eval(rows[0])
 fields, bools, counts = ((UI_FIELDS, UI_BOOLS, UI_COUNTS) if ui else
       (helper.FIELDS, helper.BOOL_FIELDS, helper.COUNT_FIELDS))
 need(type(value) is dict and set(value) == fields and
         all(type(value[key]) is bool for key in bools) and
         all(type(value[key]) is int and 0 <= value[key] <= 8192 for key in counts), 'component_fields')
 if ui:
  need(all(type(value[key]) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,95}', value[key])
                 is not None for key in UI_REASONS) and value['smoke_display_seconds'] in (0, 20), 'ui_fields')
 else: need(value['reason'] in helper.REASONS, 'stage_fields')
 return value


def accepted(value, helper, ui):
 if ui:
  return (all(value[key] is True for key in UI_SUCCESS) and value['resource_pending'] is False and
   value['auto_receive_action_issued'] is False and value['physical_ui_verified'] is False and
   value['receive_trial_claimed'] is False and value['receive_trial_claim_count'] == 0 and
   value['receive_trial_session_attached'] is False and value['interactive_window_expired'] is False and
   value['smoke_display_seconds'] == 20 and value['reason'] == 'receive_ui_smoke_finished')
 return (value['complete'] is True and value['reason'] == 'complete' and
  value['resource_pending'] is False and value['staging_pending'] is False and
  all(value[key] is True for key in helper.BOOL_FIELDS if key not in ('resource_pending', 'staging_pending')) and
  value['created_file_count'] in (0, 10) and value['created_directory_count'] in (0, 2, 3) and
  value['original_opened_fd_count'] == value['original_closed_fd_count'] > 0 and
  value['validator_opened_fd_count'] == value['validator_closed_fd_count'] == 17 and
  value['validator_files_verified'] == 10 and value['validator_readback_passes'] == 20)


def main():
 parser = argparse.ArgumentParser(description=__doc__)
 modes = parser.add_mutually_exclusive_group()
 modes.add_argument('--stage-device', action='store_true', help='Exclusive file-only staging of fixed10 UI assets.')
 modes.add_argument('--ui-smoke', action='store_true', help='True Receive profile; display launched+20s, no auto RF.')
 args = parser.parse_args()
 mode = 'stage' if args.stage_device else 'ui-smoke' if args.ui_smoke else 'source'
 out = BASE / 'results' / ('formal-receive-ui-v1-' + mode + '-' +
  datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
 private = out / 'private-raw'; private.mkdir(parents=True, exist_ok=False)
 inputs = {}; programs = {}; helper = carrier = transport = adb = before = created = launched = None
 report = dict(mode=mode, passed=False, source_checked=False, source_preserved=False,
  device_invoked=False, stage_requested=args.stage_device, ui_requested=args.ui_smoke,
  automatic_rf_action_requested=False, phone_tested=False, physical_rf_absence_verified=False,
  stage_boot_owner_credentials_requested=False, second_credential_pair=False, companion_requested=False,
  runtime_requested=False, runtime_executed=False, execution_unknown=False,
  carrier_retained=True, partial_assets_preserved=True, production_payload_roles=75,
  old_graphs=0, old_suites=0, old_builders=0, old_owner_diff_replayed=False,
  profile_seconds=600, cleanup_seconds=60, display_seconds=20, display_origin='launched',
  stage_activity_seconds=60, stage_cleanup_seconds=60, stage_alarm_seconds=180,
  physical_stdin_eof_verified=False, carrier_metadata_fixture_is_authority=False,
  host_exit='NOT_RUN', remote_exit='NOT_RUN', component=None,
  stock_before_verified=False, stock_after_verified=False, private_ui_logs_collected=False,
  error_kind=None)
 try:
  for pin in (NATIVE, UI_CARRIER, CARRIER, TRANSPORT, VALIDATOR, WORKER, DEFINITIONS):
   raw = (BASE / pin[0]).read_bytes(); need((len(raw), digest(raw)) == pin[1:], 'source_pin')
   inputs[pin[0]] = raw
  helper = definitions(NATIVE[0], inputs[NATIVE[0]], 'fixed_receive_ui_v1_native_asset_definitions')
  carrier = definitions(UI_CARRIER[0], inputs[UI_CARRIER[0]], 'fixed_receive_ui_v1_carrier_definitions')
  carrier_original = definitions(CARRIER[0], inputs[CARRIER[0]], 'fixed_receive_ui_v1_carrier_original')
  validator = definitions(VALIDATOR[0], inputs[VALIDATOR[0]], 'fixed_receive_ui_v1_assets_definitions')
  graph = definitions(DEFINITIONS[0], inputs[DEFINITIONS[0]], 'fixed_receive_ui_v1_graph_definitions')
  for path, raw in tuple(inputs.items()): need(helper.read_fixed(path) == raw, 'source_changed')
  helper = asset_helper(helper, validator)
  def read(pin):
   raw = helper.read_fixed(pin[0], pin[1:]); inputs[pin[0]] = raw; return raw
  stage = json.loads(read(STAGE_MANIFEST).decode('ascii'))
  need(validator.SESSION == SESSION and validator.REMOTE == REMOTE and
   stage['schema'] == 'p011-formal-receive-ui-v1-stage' and stage['session'] == SESSION and
   stage['remote'] == REMOTE and stage['directories'] == [dict(path=name, mode='0700') for name in ('', 'mta')] and
   tuple((row['path'], row['bytes'], row['sha256']) for row in stage['files']) == tuple(sorted(helper.ASSET_PINS)) and
   stage['staged_file_count'] == 10 and stage['payload_file_count'] == 9 and
   stage['credentials_in_stage'] is False and stage['companion_required'] is False and
   stage['single_mta_owner'] is True and stage['receive_default_tab'] is True and
   all(row['mode'] == ('0500' if row['path'] == 'Z03.mta-ui-candidate' else '0400')
    for row in stage['files']), 'stage_manifest')
  need(len(helper.PINS) == 9 and len(helper.ASSET_PINS) == 10 and
   sum(pin[1] for pin in helper.ASSET_PINS) == 4151735 < 4 * 1024 * 1024, 'asset_budget')
  for name, size, sha in helper.ASSET_PINS: read((BUNDLE + '/' + name, size, sha))
  need(inputs[BUNDLE + '/SOURCE.sha256'] == ''.join(sha + ' ' + str(size) + ' ' + name + '\n'
   for name, size, sha in helper.PINS).encode('ascii'), 'asset_manifest')
  ordinary = graph.manifest_rows(read(graph.MANIFEST))
  private_rows = graph.manifest_rows(read(graph.PRIVATE_MANIFEST), True)
  payload = ordinary + private_rows + graph.HELPERS + (graph.WPA, graph.MONITOR)
  need(len(payload) == 75 and len(ordinary) == len(private_rows) == 35 and
   len(set(row[0] for row in payload)) == 75 and sum(row[2] for row in payload) == 4129184, 'payload_roles')
  for name, path, size, sha in payload: read((path, size, sha))
  read(graph.RUNNER)
  for path in (SELF,) + CMDS: inputs[path] = helper.read_fixed(path)
  need(len(inputs[SELF]) <= 26 * 1024, 'thin_host_budget')
  ast.parse(inputs[SELF], feature_version=(3, 5))
  programs['stage'] = stage_program(helper, inputs)
  programs['ui-smoke'] = ui_program(inputs, payload, graph.RUNNER, carrier)
  body = carrier.carrier_body(carrier_original)
  for name, (program, wire) in programs.items():
   need(len(program) <= 2 * 1024 * 1024 and max(map(len, program.splitlines())) <= 2048 and
    len(wire) <= 6 * 1024 * 1024, 'program_budget')
   ast.parse(program, feature_version=(3, 5))
   write_new(out / ('private-' + name + '-bootstrap.py'), program)
   write_new(out / ('private-' + name + '-wire.raw'), wire)
  report['carrier_sources'] = carrier.check_carrier_sources(body, programs, out)
  for path, raw in inputs.items(): write_new(out / 'private-inputs' / path, raw)
  report.update(source_checked=True, asset_files=10, asset_bytes=4151735, input_count=len(inputs),
   programs={name: dict(bytes=len(program), sha256=digest(program),
    max_line=max(map(len, program.splitlines())), wire_bytes=len(wire), wire_sha256=digest(wire))
    for name, (program, wire) in programs.items()})
  if mode != 'source':
   transport = definitions(TRANSPORT[0], inputs[TRANSPORT[0]], 'fixed_receive_ui_v1_transport')
   need(Path(transport.ADB).resolve() == Path('C:/Program Files/ADB/adb.exe').resolve(), 'transport_identity')
   need(len(base64.b64encode(zlib.compress(transport.source().encode('ascii')))) + 256 <= 3500,
                 'probe_pty_fallback_forbidden')
   report['device_invoked'] = True; adb = transport.Adb(private)
   before = adb.python('stock-before', transport.source(), timeout=45)
   write_new(private / 'stock-before.private.json', (json.dumps(before) + '\n').encode('ascii'))
   report['stock_before_verified'] = carrier.stock_identity(before, transport.PINS)
   need(report['stock_before_verified'], 'stock_before')
   program, wire = programs[mode]; pins = ((len(program), digest(program)), (len(wire), digest(wire)))
   leaf = 'p011-mta-ui-carrier-v4-' + secrets.token_hex(12); remote = '/var/volatile/tmp/' + leaf
   write_new(private / 'carrier-root.private', remote.encode('ascii'))
   rec, raw, error = carrier.run_carrier(adb, private, 'carrier-create',
    carrier.carrier_source(body, 'create', leaf, pins), 30)
   report['carrier_create'] = rec; created = carrier_original.carrier_result(raw, 'create')
   need(error is None and rec['host_exit'] == rec['remote_exit'] == 0 and rec['stderr_bytes'] == 0 and
                 created['carrier_created'] and created['resources_closed'], 'carrier_create')
   for name, data in (('bootstrap.py', program), ('wire.raw', wire)):
    local = private / 'carrier-inputs' / name; write_new(local, data)
    label = 'push-' + name.split('.')[0]; stem = '%02d-%s' % (adb.index + 1, label)
    try: adb.run(label, ['push', str(local), remote + '/' + name], timeout=45)
    finally:
     rec, ignored = carrier.receipt(private, stem, 'MTA_PUSH_REMOTE_EXIT')
     report.setdefault('push_receipts', []).append(rec)
    need(rec['host_exit'] == 0, 'carrier_push')
   report['runtime_requested'] = report['execution_unknown'] = True
   rec, raw, error = carrier.run_carrier(adb, private, 'carrier-launch',
    carrier.carrier_source(body, 'launch', leaf, pins, created['root_metadata']),
    210 if mode == 'stage' else 810)
   report.update(host_exit=rec['host_exit'], remote_exit=rec['remote_exit'], carrier_launch=rec)
   launched = carrier_original.carrier_result(raw, 'launch')
   value = component(raw, helper, mode == 'ui-smoke'); report['component'] = value
   report['runtime_executed'] = True; report['execution_unknown'] = False
   need(error is None and rec['host_exit'] == rec['remote_exit'] == 0 and rec['stderr_bytes'] == 0 and
                 launched['resources_closed'] and launched['stdin_regular_verified'] and launched['stdin_closed'], 'carrier_launch')
   need(accepted(value, helper, mode == 'ui-smoke') is True, 'component_refused')
 except BaseException as error:
  report['error_kind'] = type(error).__name__
  write_new(private / 'host-error.private.txt', traceback.format_exc().encode('utf-8'))
 finally:
  if adb is not None:
   if mode == 'ui-smoke' and report['runtime_requested']:
    control = '/var/volatile/tmp/p011-mta-ui-session-' + SESSION + '-formal-receive-ui-v1'
    collected = []
    for name in ('guardian.stdout.raw', 'guardian.stderr.raw', 'candidate.stdout.raw',
                             'candidate.stderr.raw', 'guardian-after.raw'):
     try:
      target = private / 'ui-logs' / name; target.parent.mkdir(exist_ok=True)
      adb.run('pull-' + name.replace('.', '-'), ['pull', control + '/' + name, str(target)], timeout=30)
      need(target.is_file() and target.stat().st_size <=
       (1048576 if name == 'guardian-after.raw' else 4194304), 'private_ui_log')
      collected.append(name)
     except BaseException:
      write_new(private / (name + '.pull-error.private.txt'), traceback.format_exc().encode('utf-8'))
    report['private_ui_logs_collected'] = len(collected) == 5
    if len(collected) != 5 and report['error_kind'] is None: report['error_kind'] = 'PrivateUiLogError'
   if created is not None:
    try:
     rec, raw, error = carrier.run_carrier(adb, private, 'carrier-after',
      carrier.carrier_source(body, 'inspect', leaf, pins, created['root_metadata'],
       launched['files'] if launched is not None else None), 30)
     report['carrier_after'] = rec; post = carrier_original.carrier_result(raw, 'inspect')
     write_new(private / 'carrier-after.private.json', (json.dumps(post) + '\n').encode('ascii'))
     need(error is None and rec['host_exit'] == rec['remote_exit'] == 0 and rec['stderr_bytes'] == 0 and
                         post['resources_closed'] and post['files_stable'], 'carrier_after')
     report['carrier_files_after_verified'] = True
    except BaseException:
     report['carrier_files_after_verified'] = False
     if report['error_kind'] is None: report['error_kind'] = 'CarrierAfterError'
   try:
    after = adb.python('stock-after', transport.source(), timeout=45)
    write_new(private / 'stock-after.private.json', (json.dumps(after) + '\n').encode('ascii'))
    report['stock_after_verified'] = carrier.stock_identity(after, transport.PINS)
    report['stock_files_unchanged'] = before is not None and before['stock']['hashes'] == after['stock']['hashes']
    need(report['stock_after_verified'] and report['stock_files_unchanged'], 'stock_after')
   except BaseException:
    if report['error_kind'] is None: report['error_kind'] = 'StockAfterError'
  try:
   report['source_preserved'] = bool(inputs) and all(helper.read_fixed(path) == raw and
    (out / 'private-inputs' / path).read_bytes() == raw for path, raw in inputs.items())
  except BaseException: report['source_preserved'] = False
 report['passed'] = report['source_checked'] and report['source_preserved'] and report['error_kind'] is None and (
  mode == 'source' or report.get('carrier_files_after_verified') is True and report['stock_after_verified'])
 result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
 readme = (b'Default SOURCE only; explicit fixed10 files-only stage or real Receive UI smoke.\n'
  b'One true600+60 Receiver profile and one MTA pair; launched+20 display only.\n'
  b'Native stage retains original alarm180/activity60/cleanup60 and 10/20/17 validation.\n'
  b'Carrier closes retained FD>=3 before guardian fork, then separate post-inspect.\n'
  b'No large PTY source/wire stdin, sender worker, companion, auto discovery or phone action.\n'
  b'Closed stage resources clear only wrapper timer, not partial-stage failure.\n'
  b'Partial/unknown files are retained; raw stdout/stderr/exits/UI logs/input bytes stay private.\n'
  b'No old graphs/suites/builders/Owner-diff replay; SOURCE is not hardware/UI/phone/RF acceptance.\n')
 write_new(out / 'result.json', result); write_new(out / 'README.txt', readme)
 with zipfile.ZipFile(out / 'RESULTS.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
  archive.writestr('result.json', result); archive.writestr('README.txt', readme)
 with zipfile.ZipFile(out / 'RESULTS.zip') as archive:
  need(archive.namelist() == ['result.json', 'README.txt'] and archive.testzip() is None and
             archive.read('result.json') == result and archive.read('README.txt') == readme, 'public_zip')
 code = 0 if report['passed'] else 1
 write_new(out / 'checker-exit.txt', (str(code) + '\n').encode('ascii'))
 print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out), error_kind=report['error_kind'])))
 return code


if __name__ == '__main__': raise SystemExit(main())
