"""Thin fixed sender UI-v7 closure diagnostic carrier entry. Default PC SOURCE only.

The already-built/staged 19 fixed UI files are readonly validated, never restaged here.
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
SELF = 'host/device_formal_send_filecenter_ui_v7_check.py'
CMD = 'TEST_MTA_FORMAL_SEND_FILECENTER_UI_V7.cmd'
SESSION = 'a44b98dd639095d9063c9e1a'
BUNDLE = 'out/mta-ui-send-v5-'+SESSION
REMOTE = '/mnt/data/p011-toolbox/mta-ui/'+SESSION
RUNTIME = 'candidate/formal-send-filecenter-ui-v7/runtime/'
WORKER = (RUNTIME+'ui_session.py',46415,'bbbaf091f20715531e045d1b7b1a281bc78d569f5bac6089da1b105d2282dbe4')
GUARDIAN = (RUNTIME+'ui_guardian.py',43993,'30b7157cabf3dd75eb82a671a343a106c1f9e688c1ad60e12c7b8e172ffc255e')
VALIDATOR = ('candidate/formal-send-filecenter-ui-v5/runtime/ui_assets.py',12526,'ac6bffe961034558da8be607d74bc4edb62209b23ce80b8a930138a8fc7eb890')
OUTER = ('candidate/formal-send-filecenter-deploy-v5/runtime/formal_send_session.py',24059,
         '5b827482ee82e9edcf4bff07ad75e24166a4a1bda3d949a1f4f617a93dd488c3')
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
SOURCE_BASELINES = (
    ('candidate/formal-send-filecenter-ui-v6/runtime/ui_session.py',45146,
     'b4c96512767b7839245e2247d3dc1e637fe9fe694cb79c3f29f228c89d916598'),
    ('candidate/formal-send-filecenter-ui-v6/runtime/ui_guardian.py',43993,
     'da3b4d6cf3c50a3e539afb239ed01fa2e443f77066366aa727b13146aabd0a7d'),
    ('host/device_formal_send_filecenter_ui_v6_check.py',28793,
     '1a3f4930f2a75e815484f7193fb5e4c2a0ece9947ada681525a886fe6d158268'))
CONTRACT = 'tests/test_formal_socket_close_v5_linux.py'


def diagnostic_source_boundary(inputs):
    """Only the affected UI modules, no old graph/tests/builders/replay."""
    old = ast.parse(inputs[SOURCE_BASELINES[0][0]], feature_version=(3,5))
    new = ast.parse(inputs[WORKER[0]], feature_version=(3,5))
    def rows(tree):
        return {row.name: row for row in tree.body
                if isinstance(row,(ast.FunctionDef,ast.ClassDef))}
    left,right=rows(old),rows(new)
    additions={'_socket_close_observation'}
    affected={'_close_snapshot'}
    need(set(right)==set(left)|additions,'worker_definition_scope')
    need(all(ast.dump(left[name],include_attributes=False)==
             ast.dump(right[name],include_attributes=False)
             for name in left if name not in affected),'worker_unchanged_definitions')
    guardian_expected=inputs[SOURCE_BASELINES[1][0]].replace(
        b'-formal-send-filecenter-ui-v6',b'-formal-send-filecenter-ui-v7')
    need(inputs[GUARDIAN[0]]==guardian_expected,'guardian_only_control_change')
    # Both runtimes refer to the same already-frozen ELF/QRC/19 assets.
    need(b"SESSION = 'a44b98dd639095d9063c9e1a'" in inputs[WORKER[0]] and
         b"ASSETS_PIN = (12526, 'ac6bffe961034558da8be607d74bc4edb62209b23ce80b8a930138a8fc7eb890')" in inputs[WORKER[0]],
         'sealed_v5_assets_reuse')
    ast.parse(inputs[CONTRACT],feature_version=(3,5))
    return True



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
    sentinel=b'P011_FORMAL_SEND_UI_V5_SMOKE_ONLY\n'
    lines += ['wire=sys.stdin.buffer.read('+str(len(sentinel))+')',
              'if wire!='+repr(sentinel)+':raise ValueError("wire_pin")',
              'remaining=outer_until-time.monotonic()',
              'if not 0<remaining<=800.0:raise ValueError("outer_deadline")',
              'signal.setitimer(signal.ITIMER_REAL,remaining)',
              'worker=types.ModuleType("fixed_sender_ui_v7_worker")',
              'worker.__file__="<fixed-sender-ui-v7-worker>"',
              'exec(compile(sources["worker"],worker.__file__,"exec"),worker.__dict__)',
              'component=worker.run_fixed(sources["outer"],sources["guardian"],tuple(fc),sources["assets"],smoke_only=True)',
              'print("RESULT="+repr(component));print("MTA_REMOTE_OK")',
              'closed=(type(component)is dict and all(component.get(k)is True for k in ("candidate_exited","owner_closed","guardian_exited","worker_fds_closed","credentials_removed")) and component.get("resource_pending")is False)',
              'if closed:signal.setitimer(signal.ITIMER_REAL,0.0)',
              'raise SystemExit(0 if component.get("complete")is True else 1)']
    return ('\n'.join(lines)+'\n').encode('ascii'),sentinel


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
   namespace={'__name__':'formal_send_ui_v7_fixed_carrier_entry'}
   try:exec(compile(source,'<fixed-formal-send-ui-v7-bootstrap>','exec'),namespace)
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
         re.fullmatch(r'p011-mta-ui-carrier-v4-[0-9a-f]{24}',leaf)is not None,'carrier_identity')
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
             compressed+'\')),\'<fixed-ui-v7-carrier>\',\'exec\'))"; r=$?; printf \'\\nMTA_CARRIER_REMOTE_EXIT=%s\\n\' "$r"')
    need(len(command.encode('ascii'))<=4096,'carrier_command_budget')
    return command


def check_carrier_sources(body,programs,out):
    # These integers are only PC syntax/budget fixtures, never an authority
    # passed to the device. Runtime metadata still comes from actual create.
    meta_fixture=(18446744073709551615,17361641481138401520,16832,0,0,2,
                  16276538888567251425,15191436295996101330,14106333703424951235)
    file_fixture=(('bootstrap.py',meta_fixture),('wire.raw',meta_fixture[::-1]))
    leaf='p011-mta-ui-carrier-v4-'+'f'*24
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


def component(raw):
    text=raw.decode('utf-8','replace').replace('\r\r\n','\n').replace('\r\n','\n')
    rows=[line[7:] for line in text.splitlines() if line.startswith('RESULT=')]
    need(len(rows)==1 and len(rows[0])<=16384 and text.splitlines().count('MTA_REMOTE_OK')==1,'component_missing')
    value=ast.literal_eval(rows[0])
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


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device',action='store_true',help='20s display-only diagnostic; requires v5 ordinary and existing 19UI assets.')
    args=parser.parse_args();mode='ui-smoke' if args.check_device else 'source'
    out=BASE/'results'/('formal-send-filecenter-ui-v7-'+mode+'-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    private=out/'private-raw';private.mkdir(parents=True,exist_ok=False)
    inputs={};programs={};report=dict(mode=mode,passed=False,source_checked=False,source_preserved=False,
        carrier_sources_syntax_checked=False,carrier_metadata_fixture_is_authority=False,
        device_invoked=False,rf_requested=False,automatic_actions=False,phone_tested=False,
        runtime_requested=False,runtime_executed=False,execution_unknown=False,
        ui_requested=args.check_device,stage_requested=False,
        core_assets_staged_by_this_entry=False,ui_assets_restaged=False,carrier_retained=True,partial_assets_preserved=True,
        physical_stdin_eof_verified=False,old_tests=0,old_builders=0,
        diagnostic_only=True,diagnostic_grants_closure=False,diagnostic_source_boundary_verified=False,
        original_window_seconds=600,original_cleanup_seconds=60,ui_smoke_seconds=20,
        remote_alarm_seconds=800,host_timeout_seconds=810,
        host_exit='NOT_RUN',remote_exit='NOT_RUN',component=None,guard_facts_received=False,
        private_ui_logs_collected=False,unchanged_diagnostic_helper_retested=False,
        stock_before_verified=False,stock_after_verified=False,error_kind=None)
    helper=carrier=transport=adb=before=after=created=launched=None
    try:
        # Load fixed HOST definition modules only, never old main/checks.
        for pin in (ASSET_HELPER,CARRIER_HELPER,TRANSPORT,WORKER,GUARDIAN,VALIDATOR,OUTER)+SOURCE_BASELINES:
            raw=(BASE/pin[0]).read_bytes();need((len(raw),digest(raw))==pin[1:],'source_pin');inputs[pin[0]]=raw
        helper=definitions(ASSET_HELPER[0],inputs[ASSET_HELPER[0]],'fixed_sender_ui_v7_asset_generator')
        carrier=definitions(CARRIER_HELPER[0],inputs[CARRIER_HELPER[0]],'fixed_sender_ui_v7_carrier_definitions')
        validator=definitions(VALIDATOR[0],inputs[VALIDATOR[0]],'fixed_sender_ui_v7_validator_source')
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
        need(sum(row[1] for row in helper.ASSET_PINS)==4184498<4*1024*1024,'asset_budget')
        for name,size,sha in helper.ASSET_PINS:inputs[BUNDLE+'/'+name]=helper.read_fixed(BUNDLE+'/'+name,(size,sha))
        expected=''.join(sha+' '+str(size)+' '+name+'\n' for name,size,sha in helper.PINS).encode('ascii')
        need(inputs[BUNDLE+'/SOURCE.sha256']==expected,'asset_manifest')
        path='candidate/formal-send-filecenter-deploy-v3/assets/filecenter-source-manifest.json'
        inputs[path]=helper.read_fixed(path,(2466,'14d57b5aea7c49df0f87b6338044c86ccd155583994e83c8158c5217d7f48e1d'));fc=json.loads(inputs[path])['sources']
        need(len(fc)==9 and sum(row['bytes'] for row in fc)==99972,'fc_budget')
        worker_tree=ast.parse(inputs[WORKER[0]],feature_version=(3,5))
        worker_fc=next(ast.literal_eval(row.value) for row in worker_tree.body if isinstance(row,ast.Assign) and
            any(isinstance(target,ast.Name) and target.id=='FILECENTER_PINS' for target in row.targets))
        need(tuple((row['module'],row['bytes'],row['sha256']) for row in fc)==worker_fc,'fc_manifest_pins')
        for row in fc:inputs[row['source']]=helper.read_fixed(row['source'],(row['bytes'],row['sha256']))
        for path in (SELF,CMD,CONTRACT):inputs[path]=helper.read_fixed(path)
        report['diagnostic_source_boundary_verified']=diagnostic_source_boundary(inputs)
        programs['ui-smoke']=ui_program(inputs,fc)
        body=carrier_body(carrier)
        for name,(program,wire) in programs.items():
            need(len(program)<=2*1024*1024 and max(map(len,program.splitlines()))<=2048 and len(wire)<=4*1024*1024,'program_budget')
            ast.parse(program,feature_version=(3,5))
            write_new(out/('private-'+name+'-bootstrap.py'),program)
            write_new(out/('private-'+name+'-wire.raw'),wire)
        carrier_sources=check_carrier_sources(body,programs,out)
        for path,raw in inputs.items():write_new(out/'private-inputs'/path,raw)
        report.update(source_checked=True,carrier_sources_syntax_checked=True,carrier_sources=carrier_sources,
            input_count=len(inputs),asset_bytes=4184498,asset_files=19,
            filecenter_source_bytes=99972,programs={name:dict(bytes=len(program),sha256=digest(program),
            max_line=max(map(len,program.splitlines())),wire_bytes=len(wire),wire_sha256=digest(wire))
            for name,(program,wire) in programs.items()})
        if mode!='source':
            transport=definitions(TRANSPORT[0],inputs[TRANSPORT[0]],'fixed_sender_ui_v7_transport')
            need(Path(transport.ADB).resolve()==Path('C:/Program Files/ADB/adb.exe').resolve(),'transport_identity')
            probe_encoded=base64.b64encode(zlib.compress(transport.source().encode('utf-8'))).decode('ascii')
            need(len(probe_encoded)+256<=3500,'probe_pty_fallback_forbidden')
            report['device_invoked']=True;adb=transport.Adb(private)
            before=adb.python('stock-before',transport.source(),timeout=45)
            write_new(private/'stock-before.private.json',(json.dumps(before,sort_keys=True)+'\n').encode('ascii'))
            report['stock_before_verified']=stock_identity(before,transport.PINS);need(report['stock_before_verified'],'stock_before')
            program,wire=programs[mode];pins=((len(program),digest(program)),(len(wire),digest(wire)))
            leaf='p011-mta-ui-carrier-v4-'+secrets.token_hex(12);remote='/var/volatile/tmp/'+leaf
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
            value=component(raw);report['component']=value
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
                control='/var/volatile/tmp/p011-mta-ui-session-'+SESSION+'-formal-send-filecenter-ui-v7'
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
    readme=(b'Default PC SOURCE only. Explicit 20s UI display diagnostic; no asset staging.\n'
        b'Original600+60 and guardian+68/+135 remain; no automatic RF/business/audio.\n'
        b'No large PTY stdin: EXCL carrier, exact source/wire SHA, regular fd0.\n'
        b'Carrier launcher closes all retained FD>=3 before guardian fork; separate post-inspect.\n'
        b'Partial/unknown assets and carriers are retained, not retried or deleted.\n'
        b'Raw source/stdout/stderr/exits/private UI logs remain local; ZIP is result+README only.\n'
        b'No old suites, graph, builders or diagnostic fixture replay; SOURCE is not device/visual/phone/RF acceptance.\n')
    write_new(out/'result.json',result);write_new(out/'README.txt',readme)
    with zipfile.ZipFile(out/'RESULTS.zip','x',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json',result);archive.writestr('README.txt',readme)
    with zipfile.ZipFile(out/'RESULTS.zip') as archive:
        need(archive.namelist()==['result.json','README.txt'] and archive.testzip() is None and
             archive.read('result.json')==result and archive.read('README.txt')==readme,'public_zip')
    code=0 if report['passed'] else 1
    write_new(out/'checker-exit.txt',(str(code)+'\n').encode('ascii'))
    print(json.dumps(dict(passed=report['passed'],mode=mode,result_dir=str(out),error_kind=report['error_kind'])))
    return code


if __name__=='__main__':raise SystemExit(main())
