"""Thin fixed sender UI-v3 carrier entry. Default PC SOURCE only.

--stage-device exclusively stages the 19 fixed files, never UI/Owner/RF.
--check-device explicitly launches a 20s display-only smoke under the original
600+60 UI/Owner cap and real guardian. No automatic scan/send/receive/audio.
Carrier source/wire use adb push, not large legacy PTY stdin. Carrier and partial
assets stay retained; no overwrite, deletion, chmod, retry or history handling.
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
SELF = 'host/device_formal_send_filecenter_ui_v3_check.py'
CMD = 'TEST_MTA_FORMAL_SEND_FILECENTER_UI_V3.cmd'
SESSION = '75ff78ef1ee74591a1a39501'
BUNDLE = 'out/mta-ui-send-v2-'+SESSION
REMOTE = '/mnt/data/p011-toolbox/mta-ui/'+SESSION
RUNTIME = 'candidate/formal-send-filecenter-ui-v3/runtime/'
WORKER = (RUNTIME+'ui_session.py',34436,'15d4a09b7675e4d1234f8ad8941bac6b2543c385491b795552358dea0e9f6aae')
GUARDIAN = (RUNTIME+'ui_guardian.py',43993,'053f99e012cfd2dbc85bd9d23b01abb9b43e152918b8d6c78325cc6adc8f99fd')
VALIDATOR = ('candidate/formal-send-filecenter-ui-v2/runtime/ui_assets.py',12526,'41f071cef365de693a0cb41f44f431e448d26d0e9978a8a6d9d116b1e82f6adb')
OUTER = ('candidate/formal-send-filecenter-deploy-v3/runtime/formal_send_session.py',24059,
         '010372da6947869cc4bce3b6ce5471fe36c389bef4ad057981e5f6246a6f519a')
ASSET_HELPER = ('host/device_receive_filecenter_assets_v1_check.py',46084,
                'cd5dc6cdf074a71d5309b1444e37c2fa0489c0fd5ca62e9fba9860eaa9f8c5e9')
CARRIER_HELPER = ('host/device_formal_send_filecenter_stage_carrier_v3_check.py',25857,
                  '043844b6be906369ad16b17562030629213a127756adb73c849b7b7b4c10ff0d')
TRANSPORT = ('host/device_probe.py',8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
UI_BOOLS = ('complete','ui_ready','credentials_removed','original_ui_exited','candidate_exited',
    'owner_closed','guardian_exited','stock_restored','worker_fds_closed','resource_pending',
    'automatic_rf_action','receive_worker_started','filecenter_parent_deadline_verified',
    'filecenter_parent_deadline_wired','smoke_requested')
UI_FIELDS = frozenset(UI_BOOLS+('automatic_stop_seconds','reason'))
UI_REASONS = ('sender_ui_smoke_finished','sender_ui_finished','interactive_window_expired')


def need(value,code):
    if value is not True: raise ValueError(code)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def write_new(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as handle: need(handle.write(raw)==len(raw),'host_write')


def definitions(path,raw,name):
    module=types.ModuleType(name);module.__file__=str(BASE/path)
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module


def encoded(raw):
    data=base64.b64encode(zlib.compress(raw,9)).decode('ascii')
    return '\n'.join(' '+repr(data[at:at+256]) for at in range(0,len(data),256))


def ui_program(inputs,fc_rows):
    raw_rows=((WORKER[0],'worker',WORKER[1:]),(OUTER[0],'outer',OUTER[1:]),
              (GUARDIAN[0],'guardian',GUARDIAN[1:]),(VALIDATOR[0],'assets',VALIDATOR[1:]))
    lines=['import base64,hashlib,signal,sys,time,types,zlib',
           'started=time.monotonic();outer_until=started+800.0',
           'signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(20)',
           'def decode(data,size,sha):',
           ' d=zlib.decompressobj();raw=d.decompress(base64.b64decode(data,validate=True),size+1)',
           ' if len(raw)!=size or not d.eof or d.unused_data or d.unconsumed_tail or hashlib.sha256(raw).hexdigest()!=sha:raise ValueError("source_pin")',
           ' return raw','sources={}']
    for path,name,pin in raw_rows:
        lines.append('sources['+repr(name)+']=decode((\n'+encoded(inputs[path])+'),'+repr(pin[0])+','+repr(pin[1])+')')
    lines.append('fc=[]')
    for row in fc_rows:
        lines.append('fc.append(('+repr(row['module'])+',decode((\n'+encoded(inputs[row['source']])+'),'+
                     repr(row['bytes'])+','+repr(row['sha256'])+')))')
    sentinel=b'P011_FORMAL_SEND_UI_V3_SMOKE_ONLY\n'
    lines += ['wire=sys.stdin.buffer.read('+str(len(sentinel))+')',
              'if wire!='+repr(sentinel)+':raise ValueError("wire_pin")',
              'remaining=outer_until-time.monotonic()',
              'if not 0<remaining<=800.0:raise ValueError("outer_deadline")',
              'signal.setitimer(signal.ITIMER_REAL,remaining)',
              'worker=types.ModuleType("fixed_sender_ui_v3_worker")',
              'worker.__file__="<fixed-sender-ui-v3-worker>"',
              'exec(compile(sources["worker"],worker.__file__,"exec"),worker.__dict__)',
              'component=worker.run_fixed(sources["outer"],sources["guardian"],tuple(fc),sources["assets"],smoke_only=True)',
              'print("RESULT="+repr(component));print("MTA_REMOTE_OK")',
              'closed=(type(component)is dict and all(component.get(k)is True for k in ("candidate_exited","owner_closed","guardian_exited","worker_fds_closed","credentials_removed")) and component.get("resource_pending")is False)',
              'if closed:signal.setitimer(signal.ITIMER_REAL,0.0)',
              'raise SystemExit(0 if component.get("complete")is True else 1)']
    return ('\n'.join(lines)+'\n').encode('ascii'),sentinel


def stage_program(helper,inputs):
    source,wire=helper.make_source(inputs)
    # The exact old TARGET is only a pinned fixed generator template. The new
    # bootstrap consumes its real result; no old checker main or test runs.
    body=('import signal,sys\nsignal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(180)\n'+
          'namespace={"__name__":"fixed_sender_ui_v3_asset_stage"}\n'+
          'status=1\ntry:\n exec(compile('+repr(source)+',"<fixed-sender-ui-v3-asset-stage>","exec"),namespace)\n'+
          'except SystemExit as error:\n status=error.code\n'+
          'component=namespace.get("component")\n'+
          'if type(component)is dict and component.get("original_fds_closed")is True and component.get("resource_pending")is False:signal.setitimer(signal.ITIMER_REAL,0.0)\n'+
          'raise SystemExit(status)\n')
    # Split the compiled stage text itself into bounded repr pieces; no huge
    # source literal line is carried through legacy PTY or generated envelopes.
    literal='(\n'+ '\n'.join(' '+repr(source[at:at+256]) for at in range(0,len(source),256))+'\n)'
    body=body.replace(repr(source),literal)
    return body.encode('ascii'),wire


def carrier_body(original):
    body=original.CARRIER_BODY
    body=body.replace('whole_until=started+200.0','whole_until=started+810.0')
    before=body.index('   signal.alarm(0)\n   timer_may_clear=False')
    after=body.index('\n  current();need(os.lseek(root',before)
    body=body[:before]+'''   # Close every original launcher FD >=3 BEFORE UI guardian fork.
   need(close(wire_row))
   for original in reversed(rows):need(close(original))
   need(all(r['closed']and not r['unknown']for r in rows))
   signal.alarm(0);timer_may_clear=False
   namespace={'__name__':'formal_send_ui_v3_fixed_carrier_entry'}
   try:exec(compile(source,'<fixed-formal-send-ui-v3-bootstrap>','exec'),namespace)
   except BaseException as e:failure=e
   need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0))
   timer_may_clear=True
   need(meta(os.fstat(0))==stdin_expected)
''' +body[after:]
    start=body.index('  current();need(os.lseek(root')
    end=body.index('\n result={',start)
    body=body[:start]+'''  if MODE!='launch':
   current();need(os.lseek(root['fd'],0,os.SEEK_SET)==0)
   need(sorted(os.listdir(root['fd']))==['bootstrap.py','wire.raw']and
        meta(os.fstat(root['fd']))==original_root)
   for name,m in files:need(meta(os.stat(name,dir_fd=root['fd'],follow_symlinks=False))==m)
   files_stable=True
  # Launch has a separate real post-inspect; no false after-stability receipt.
''' +body[end:]
    return body


def carrier_source(body,mode,leaf,pins,root=None,files=None):
    need(mode in ('create','launch','inspect') and
         re.fullmatch(r'p011-mta-ui-carrier-v3-[0-9a-f]{24}',leaf)is not None,'carrier_identity')
    body='\n'.join(line for line in body.splitlines() if not line.lstrip().startswith('#'))+'\n'
    return ('MODE='+repr(mode)+'\nLEAF='+repr(leaf)+'\nFILE_MODES='+repr((0o600,0o640,0o644,0o660,0o664,0o666))+
            '\nBOOTSTRAP_PIN='+repr(pins[0])+'\nWIRE_PIN='+repr(pins[1])+
            '\nEXPECTED_ROOT='+repr(root)+'\nEXPECTED_FILES='+repr(files)+'\n'+body)


def remote_exit(raw,marker):
    text=raw.decode('utf-8','replace').replace('\r\r\n','\n').replace('\r\n','\n')
    rows=re.findall(r'^'+marker+r'=(-?\d+)$',text,re.M)
    return int(rows[0]) if len(rows)==1 else 'UNKNOWN'


def receipt(private,stem,marker):
    value={'host_exit':'NOT_RUN','remote_exit':'UNKNOWN','stderr_bytes':None}
    raw=b''
    for tag in ('stdout','stderr'):
        path=private/(stem+'.'+tag+'.raw')
        if path.exists():
            data=path.read_bytes();value[tag+'_bytes']=len(data);value[tag+'_sha256']=digest(data)
            if tag=='stdout':raw=data
    path=private/(stem+'.host-exit')
    if path.exists():
        code=path.read_text(encoding='ascii').strip()
        value['host_exit']=int(code) if re.fullmatch(r'-?\d+',code) else 'TIMEOUT'
    value['remote_exit']=remote_exit(raw,marker)
    write_new(private/(stem+'.remote-exit'),(str(value['remote_exit'])+'\n').encode('ascii'))
    return value,raw


def carrier_command(source):
    compressed=base64.b64encode(zlib.compress(source.encode('ascii'),9)).decode('ascii')
    command=('/usr/bin/python3.5 -I -B -c "import base64,zlib;exec(compile(zlib.decompress(base64.b64decode(\''+
             compressed+'\')),\'<fixed-ui-v3-carrier>\',\'exec\'))"; r=$?; printf \'\\nMTA_CARRIER_REMOTE_EXIT=%s\\n\' "$r"')
    need(len(command.encode('ascii'))<=4096,'carrier_command_budget')
    return command


def check_carrier_sources(body,programs,out):
    # These integers are only PC syntax/budget fixtures, never an authority
    # passed to the device. Runtime metadata still comes from actual create.
    meta_fixture=(18446744073709551615,17361641481138401520,16832,0,0,2,
                  16276538888567251425,15191436295996101330,14106333703424951235)
    file_fixture=(('bootstrap.py',meta_fixture),('wire.raw',meta_fixture[::-1]))
    leaf='p011-mta-ui-carrier-v3-'+'f'*24
    checked=[]
    for name,(program,wire) in programs.items():
        pins=((len(program),digest(program)),(len(wire),digest(wire)))
        for mode in ('create','launch','inspect'):
            source=carrier_source(body,mode,leaf,pins,
                None if mode=='create' else meta_fixture,
                file_fixture if mode=='inspect' else None)
            ast.parse(source,feature_version=(3,5))
            need(max(map(len,source.splitlines()))<=2048,'carrier_source_line_budget')
            command=carrier_command(source)
            write_new(out/('private-carrier-'+name+'-'+mode+'.py'),source.encode('ascii'))
            checked.append(dict(program=name,phase=mode,source_bytes=len(source),
                source_sha256=digest(source.encode('ascii')),command_bytes=len(command.encode('ascii'))))
    return checked


def run_carrier(adb,private,label,source,timeout):
    command=carrier_command(source)
    write_new(private/(label+'.source.private.py'),source.encode('ascii'))
    write_new(private/(label+'.command.private'),command.encode('ascii'))
    stem='%02d-%s'%(adb.index+1,label);failure=None
    try:adb.run(label,['shell',command],timeout=timeout)
    except BaseException as error:failure=error
    value,raw=receipt(private,stem,'MTA_CARRIER_REMOTE_EXIT')
    return value,raw,failure


def component(raw,mode,asset_helper):
    text=raw.decode('utf-8','replace').replace('\r\r\n','\n').replace('\r\n','\n')
    rows=[line[7:] for line in text.splitlines() if line.startswith('RESULT=')]
    need(len(rows)==1 and len(rows[0])<=16384 and text.splitlines().count('MTA_REMOTE_OK')==1,'component_missing')
    value=ast.literal_eval(rows[0])
    if mode=='stage':
        need(type(value)is dict and set(value)==asset_helper.FIELDS and
             all(type(value[key])is bool for key in asset_helper.BOOL_FIELDS) and
             all(type(value[key])is int for key in asset_helper.COUNT_FIELDS),'stage_fields')
    else:
        need(type(value)is dict and set(value)==UI_FIELDS and
             all(type(value[key])is bool for key in UI_BOOLS) and
             type(value['automatic_stop_seconds'])is int and value['automatic_stop_seconds']==20 and
             type(value['reason'])is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,95}',value['reason'])is not None,
             'ui_fields')
    return value


def stock_identity(value,pins):
    if type(value)is not dict or value.get('stock',{}).get('hashes')!=pins:return False
    rows=value['stock']['processes']
    return all(sum(row['name']==name and (name=='weston' or row['exe']=='/usr/bin/'+name)
                   for row in rows)==1 for name in ('Z03','control_engine','weston'))


def diagnostic_projection_check(raw):
    """Execute only the new pure exception formatter with explicit HOST errors."""
    tree=ast.parse(raw,feature_version=(3,5))
    names={'SenderUiError','_need','_exception_projection'}
    constants={'DIAGNOSTIC_STAGES','DIAGNOSTIC_LIMIT'}
    selected=[node for node in tree.body if
        isinstance(node,(ast.ClassDef,ast.FunctionDef)) and node.name in names or
        isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and
            target.id in constants for target in node.targets)]
    need(len(selected)==5,'diagnostic_selected_scope')
    namespace={'__name__':'fixed_sender_ui_v3_projection_host','re':re}
    exec(compile(ast.fix_missing_locations(ast.Module(body=selected,type_ignores=[])),
        '<selected-diagnostic-helper>','exec'),namespace)
    fixture=('def origin():\n raise FileNotFoundError(2,"DO_NOT_OUTPUT_ARGUMENT",'
             '"/private/DO_NOT_OUTPUT_FILENAME")\n'
             'def chained():\n try:origin()\n'
             ' except FileNotFoundError as cause:raise RuntimeError("DO_NOT_OUTPUT_TOKEN") from cause\n')
    exec(compile(fixture,'/private/DO_NOT_OUTPUT_SOURCE_PATH','exec'),namespace)
    try:namespace['chained']()
    except RuntimeError as error:actual=error
    project=namespace['_exception_projection']
    projected=project([actual],['scope_created','sender_start'])
    value=ast.literal_eval(projected.decode('ascii'))
    need(value['failure_count']==1 and value['stages']==('scope_created','sender_start') and
        value['errors'][0][0]['kind']=='RuntimeError' and
        value['errors'][0][1]['relation']=='cause' and
        value['errors'][0][1]['kind']=='FileNotFoundError' and
        value['errors'][0][1]['errno']==2 and not value['truncated'] and
        b'DO_NOT_OUTPUT' not in projected and b'/private/' not in projected,
        'diagnostic_actual_chain')
    empty=ast.literal_eval(project([],['scope_created']).decode('ascii'))
    need(empty['errors']==() and empty['failure_count']==0,'diagnostic_empty')
    try:project([actual],['not_a_real_stage'])
    except namespace['SenderUiError']:pass
    else:raise ValueError('diagnostic_unknown_stage')
    actual.__cause__=actual
    cycle=ast.literal_eval(project([actual],['sender_start']).decode('ascii'))
    need(cycle['truncated'] is True and len(cycle['errors'][0])==1,'diagnostic_cycle')
    return dict(cases=4,actual_selected_pure_helper=True,errors_are_host_fixtures=True,
                runtime_owner_guardian_not_executed=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    choice=parser.add_mutually_exclusive_group()
    choice.add_argument('--stage-device',action='store_true')
    choice.add_argument('--check-device',action='store_true')
    args=parser.parse_args();mode='stage' if args.stage_device else 'ui-smoke' if args.check_device else 'source'
    out=BASE/'results'/('formal-send-filecenter-ui-v3-'+mode+'-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    private=out/'private-raw';private.mkdir(parents=True,exist_ok=False)
    inputs={};programs={};report=dict(mode=mode,passed=False,source_checked=False,source_preserved=False,
        carrier_sources_syntax_checked=False,carrier_metadata_fixture_is_authority=False,
        device_invoked=False,rf_requested=False,automatic_actions=False,phone_tested=False,
        runtime_requested=False,runtime_executed=False,execution_unknown=False,
        ui_requested=args.check_device,stage_requested=args.stage_device,
        core_assets_staged_by_this_entry=False,carrier_retained=True,partial_assets_preserved=True,
        physical_stdin_eof_verified=False,old_tests=0,old_builders=0,
        original_window_seconds=600,original_cleanup_seconds=60,ui_smoke_seconds=20,
        remote_alarm_seconds=800 if args.check_device else 180,host_timeout_seconds=810 if args.check_device else 210,
        host_exit='NOT_RUN',remote_exit='NOT_RUN',component=None,guard_facts_received=False,
        private_ui_logs_collected=False,diagnostic_projection_checked=False,
        stock_before_verified=False,stock_after_verified=False,error_kind=None)
    helper=carrier=transport=adb=before=after=created=launched=None
    try:
        # Load fixed HOST definition modules only, never old main/checks.
        for pin in (ASSET_HELPER,CARRIER_HELPER,TRANSPORT,WORKER,GUARDIAN,VALIDATOR,OUTER):
            raw=(BASE/pin[0]).read_bytes();need((len(raw),digest(raw))==pin[1:],'source_pin');inputs[pin[0]]=raw
        helper=definitions(ASSET_HELPER[0],inputs[ASSET_HELPER[0]],'fixed_sender_ui_v3_asset_generator')
        carrier=definitions(CARRIER_HELPER[0],inputs[CARRIER_HELPER[0]],'fixed_sender_ui_v3_carrier_definitions')
        validator=definitions(VALIDATOR[0],inputs[VALIDATOR[0]],'fixed_sender_ui_v3_validator_source')
        helper.SESSION,helper.BUNDLE,helper.REMOTE,helper.VALIDATOR=SESSION,BUNDLE,REMOTE,VALIDATOR
        manifest_path=BUNDLE+'/stage-manifest.json';inputs[manifest_path]=helper.read_fixed(manifest_path)
        stage=json.loads(inputs[manifest_path])
        need(stage['session']==SESSION and stage['remote']==REMOTE and len(stage['files'])==19,'stage_manifest')
        # Only the pinned validator supplies pins; a changed PC manifest may
        # never cause even a conflicting ELF to be written before rejection.
        helper.PINS=validator.PINS
        helper.MANIFEST=('SOURCE.sha256',)+validator.MANIFEST_PIN
        helper.ASSET_PINS=helper.PINS+(helper.MANIFEST,)
        need(tuple((row['path'],row['bytes'],row['sha256']) for row in stage['files'])==
             tuple(sorted(helper.ASSET_PINS)) and
             stage['directories']==[dict(path=name,mode='0700') for name in ('','mta','toolbox')] and
             all(row['mode']==('0500' if row['path']=='Z03.mta-ui-candidate' else '0400')
                 for row in stage['files']) and stage['credentials_in_stage'] is False,'stage_manifest_pins')
        need(sum(row[1] for row in helper.ASSET_PINS)==4182242<4*1024*1024,'asset_budget')
        helper.TARGET=helper.TARGET.replace('4182249','4182242').replace(
            "(12509,'63080e070df39cd10a94e6a8d1f3e2bb3d2e8a6fd877f78c334fc8adb87360a5')",repr(VALIDATOR[1:]))
        need('4182249' not in helper.TARGET and '12509' not in helper.TARGET,'target_old_pins')
        for name,size,sha in helper.ASSET_PINS:inputs[BUNDLE+'/'+name]=helper.read_fixed(BUNDLE+'/'+name,(size,sha))
        expected=''.join(sha+' '+str(size)+' '+name+'\n' for name,size,sha in helper.PINS).encode('ascii')
        need(inputs[BUNDLE+'/SOURCE.sha256']==expected,'asset_manifest')
        path='candidate/formal-send-filecenter-deploy-v3/assets/filecenter-source-manifest.json'
        inputs[path]=helper.read_fixed(path);fc=json.loads(inputs[path])['sources']
        need(len(fc)==9 and sum(row['bytes'] for row in fc)==99972,'fc_budget')
        worker_tree=ast.parse(inputs[WORKER[0]],feature_version=(3,5))
        worker_fc=next(ast.literal_eval(row.value) for row in worker_tree.body if isinstance(row,ast.Assign) and
            any(isinstance(target,ast.Name) and target.id=='FILECENTER_PINS' for target in row.targets))
        need(tuple((row['module'],row['bytes'],row['sha256']) for row in fc)==worker_fc,'fc_manifest_pins')
        for row in fc:inputs[row['source']]=helper.read_fixed(row['source'],(row['bytes'],row['sha256']))
        for path in (SELF,CMD):inputs[path]=helper.read_fixed(path)
        programs['stage']=stage_program(helper,inputs);programs['ui-smoke']=ui_program(inputs,fc)
        body=carrier_body(carrier)
        for name,(program,wire) in programs.items():
            need(len(program)<=2*1024*1024 and max(map(len,program.splitlines()))<=2048 and len(wire)<=6*1024*1024,'program_budget')
            ast.parse(program,feature_version=(3,5))
            write_new(out/('private-'+name+'-bootstrap.py'),program)
            write_new(out/('private-'+name+'-wire.raw'),wire)
        carrier_sources=check_carrier_sources(body,programs,out)
        projection=diagnostic_projection_check(inputs[WORKER[0]])
        for path,raw in inputs.items():write_new(out/'private-inputs'/path,raw)
        report.update(source_checked=True,carrier_sources_syntax_checked=True,carrier_sources=carrier_sources,
            diagnostic_projection_checked=True,diagnostic_projection=projection,
            input_count=len(inputs),asset_bytes=4182242,asset_files=19,
            filecenter_source_bytes=99972,programs={name:dict(bytes=len(program),sha256=digest(program),
            max_line=max(map(len,program.splitlines())),wire_bytes=len(wire),wire_sha256=digest(wire))
            for name,(program,wire) in programs.items()})
        if mode!='source':
            transport=definitions(TRANSPORT[0],inputs[TRANSPORT[0]],'fixed_sender_ui_v3_transport')
            need(Path(transport.ADB).resolve()==Path('C:/Program Files/ADB/adb.exe').resolve(),'transport_identity')
            probe_encoded=base64.b64encode(zlib.compress(transport.source().encode('utf-8'))).decode('ascii')
            need(len(probe_encoded)+256<=3500,'probe_pty_fallback_forbidden')
            report['device_invoked']=True;adb=transport.Adb(private)
            before=adb.python('stock-before',transport.source(),timeout=45)
            write_new(private/'stock-before.private.json',(json.dumps(before,sort_keys=True)+'\n').encode('ascii'))
            report['stock_before_verified']=stock_identity(before,transport.PINS);need(report['stock_before_verified'],'stock_before')
            program,wire=programs[mode];pins=((len(program),digest(program)),(len(wire),digest(wire)))
            leaf='p011-mta-ui-carrier-v3-'+secrets.token_hex(12);remote='/var/volatile/tmp/'+leaf
            write_new(private/'carrier-root.private',remote.encode('ascii'))
            rec,raw,error=run_carrier(adb,private,'carrier-create',carrier_source(body,'create',leaf,pins),30)
            report['carrier_create']=rec;created=carrier.carrier_result(raw,'create')
            write_new(private/'carrier-create.private.json',(json.dumps(created)+'\n').encode('ascii'))
            need(error is None and rec['host_exit']==rec['remote_exit']==0 and rec['stderr_bytes']==0 and
                 created['carrier_created'] and created['resources_closed'],'carrier_create')
            for name,data in (('bootstrap.py',program),('wire.raw',wire)):
                local=private/'carrier-inputs'/name;write_new(local,data)
                label='push-'+name.split('.')[0];stem='%02d-%s'%(adb.index+1,label)
                try:adb.run(label,['push',str(local),remote+'/'+name],timeout=45)
                finally:
                    rec,ignored=receipt(private,stem,'MTA_PUSH_REMOTE_EXIT');report.setdefault('push_receipts',[]).append(rec)
                need(rec['host_exit']==0,'carrier_push')
            report['runtime_requested']=report['execution_unknown']=True
            rec,raw,error=run_carrier(adb,private,'carrier-launch',carrier_source(body,'launch',leaf,pins,created['root_metadata']),
                                      report['host_timeout_seconds'])
            report.update(host_exit=rec['host_exit'],remote_exit=rec['remote_exit'],carrier_launch=rec)
            # Remote exit is saved BEFORE parsing may reject missing RESULT.
            launched=carrier.carrier_result(raw,'launch')
            write_new(private/'carrier-launch.private.json',(json.dumps(launched)+'\n').encode('ascii'))
            value=component(raw,'stage' if mode=='stage' else 'ui',helper);report['component']=value
            report['runtime_executed']=True;report['execution_unknown']=False
            report['guard_facts_received']=mode=='ui-smoke'
            need(error is None and rec['host_exit']==rec['remote_exit']==0 and rec['stderr_bytes']==0 and
                 launched['resources_closed'] and launched['stdin_regular_verified'] and launched['stdin_closed'],
                 'carrier_launch')
            need(value['complete'] is True and value['resource_pending'] is False,'component_refused')
            if mode=='ui-smoke':
                need(value['smoke_requested'] is True and value['reason'] in UI_REASONS and
                     value['automatic_rf_action'] is False and value['receive_worker_started'] is False and
                     all(value[key] is True for key in ('ui_ready','owner_closed','guardian_exited','stock_restored',
                                                       'candidate_exited','credentials_removed','worker_fds_closed')),
                     'ui_smoke_refused')
    except BaseException as error:
        report['error_kind']=type(error).__name__
        write_new(private/'host-error.private.txt',traceback.format_exc().encode('utf-8'))
    finally:
        if adb is not None:
            if mode=='ui-smoke' and report['runtime_requested']:
                # Read only the five fixed private files, including on failure;
                # missing/partial diagnostics never turn unknown closure True.
                control='/var/volatile/tmp/p011-mta-ui-session-'+SESSION+'-formal-send-filecenter-ui-v3'
                collected=[]
                for name in ('guardian.stdout.raw','guardian.stderr.raw','candidate.stdout.raw',
                             'candidate.stderr.raw','worker.diagnostic.raw'):
                    try:
                        target=private/'ui-logs'/name;target.parent.mkdir(exist_ok=True)
                        adb.run('pull-'+name.replace('.','-'),['pull',control+'/'+name,str(target)],timeout=30)
                        need(target.is_file() and target.stat().st_size<=
                            (32768 if name=='worker.diagnostic.raw' else 4*1024*1024),'private_ui_log')
                        collected.append(name)
                    except BaseException:
                        write_new(private/(name+'.pull-error.private.txt'),traceback.format_exc().encode('utf-8'))
                report['private_ui_logs_collected']=len(collected)==5
                report['private_diagnostic_collected']='worker.diagnostic.raw' in collected
                if len(collected)!=5 and report['error_kind'] is None:report['error_kind']='PrivateUiLogError'
            if created is not None:
                try:
                    rec,raw,error=run_carrier(adb,private,'carrier-after',carrier_source(body,'inspect',leaf,pins,
                        created['root_metadata'],launched['files'] if launched is not None else None),30)
                    report['carrier_after']=rec;post=carrier.carrier_result(raw,'inspect')
                    write_new(private/'carrier-after.private.json',(json.dumps(post)+'\n').encode('ascii'))
                    need(error is None and rec['host_exit']==rec['remote_exit']==0 and rec['stderr_bytes']==0 and
                         post['resources_closed'] and post['files_stable'],'carrier_after')
                    report['carrier_files_after_verified']=True
                except BaseException:
                    report['carrier_files_after_verified']=False
                    if report['error_kind'] is None:report['error_kind']='CarrierAfterError'
            try:
                after=adb.python('stock-after',transport.source(),timeout=45)
                write_new(private/'stock-after.private.json',(json.dumps(after,sort_keys=True)+'\n').encode('ascii'))
                report['stock_after_verified']=stock_identity(after,transport.PINS)
                report['stock_files_unchanged']=before is not None and before['stock']['hashes']==after['stock']['hashes']
                need(report['stock_after_verified'] and report['stock_files_unchanged'],'stock_after')
            except BaseException:
                if report['error_kind'] is None:report['error_kind']='StockAfterError'
        try:
            report['source_preserved']=bool(inputs) and all((BASE/path).read_bytes()==raw and
                (out/'private-inputs'/path).read_bytes()==raw for path,raw in inputs.items())
        except BaseException:report['source_preserved']=False
    report['passed']=report['source_checked'] and report['source_preserved'] and report['error_kind'] is None and (
        mode=='source' or report.get('carrier_files_after_verified') is True and report['stock_after_verified'])
    result=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode('ascii')
    readme=(b'Default PC SOURCE only. Explicit files-only stage or 20s UI display smoke.\n'
        b'Original600+60 and guardian+68/+135 remain; no automatic RF/business/audio.\n'
        b'No large PTY stdin: EXCL carrier, exact source/wire SHA, regular fd0.\n'
        b'Carrier launcher closes all retained FD>=3 before guardian fork; separate post-inspect.\n'
        b'Partial/unknown assets and carriers are retained, not retried or deleted.\n'
        b'Raw source/stdout/stderr/exits/private UI logs remain local; ZIP is result+README only.\n'
        b'PC SOURCE/build is not device/visual/phone or RF acceptance.\n')
    write_new(out/'result.json',result);write_new(out/'README.txt',readme)
    with zipfile.ZipFile(out/'RESULTS.zip','x',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json',result);archive.writestr('README.txt',readme)
    print(json.dumps(dict(passed=report['passed'],mode=mode,result_dir=str(out),error_kind=report['error_kind'])))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
