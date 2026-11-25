"""Versioned fixed WPA facts collector: observed namespace profiles only.

No STATUS/socket/RF/admission; the original be59 source and failure stay intact.
"""
import argparse
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types
import zipfile

BASE = Path(__file__).absolute().parents[1]
ROOT = BASE.parents[1]
LEGACY_PIN = 'be59afc4ebda920db84075d509a1dec4e630a70590263eefa5754b9c13a2ad56'
PROFILES = ('not_recorded', 'full4_present', 'namespaces_disabled_cgroup_mnt')
SOURCE_VERSION = 'wpa-profile-v2-owned-path-links'
_EXECUTIONS = []

PROFILE_CODE = r'''
import zlib
def namespace_config(raw):
 if type(raw) is not bytes or not 1<=len(raw)<=262144:fail('namespace_config')
 try:
  decoder=zlib.decompressobj(31);plain=decoder.decompress(raw,1048577)
  if len(plain)>1048576 or decoder.unconsumed_tail or not decoder.eof or decoder.unused_data:fail('namespace_config')
  if decoder.flush() or not plain.endswith(b'\n') or b'\0' in plain:fail('namespace_config')
  plain.decode('ascii','strict')
 except (zlib.error,UnicodeError):fail('namespace_config')
 setting=tuple(line for line in plain.splitlines() if line.startswith((b'CONFIG_NAMESPACES',b'# CONFIG_NAMESPACES')))
 if setting!=(b'# CONFIG_NAMESPACES is not set',):fail('namespace_config')
 return hashlib.sha256(plain).hexdigest()
def namespace_observe(obj,actor):
 roots=('/proc/'+str(actor.pid)+'/ns','/proc/self/ns');directories=tuple(tuple(sorted(obj.names(root,8))) for root in roots)
 obj.private.setdefault('namespace_directories',[]).append((roots,directories))
 known=('cgroup','ipc','mnt','net','pid','pid_for_children','user','uts')
 if any(len(set(names))!=len(names) or any(name not in known for name in names) for names in directories) or directories[0]!=directories[1]:fail('namespace_profile')
 names=directories[0];full=set(('mnt','net','pid','user')).issubset(names)
 if full:kind='full4_present';config=None;state='NOT_EVALUATED'
 elif names==('cgroup','mnt'):
  config=namespace_config(obj.files.read('/proc/config.gz',262144));kind='namespaces_disabled_cgroup_mnt';state='disabled'
 else:fail('namespace_profile')
 links=[]
 for name in names:
  pair=tuple(obj.link(root+'/'+name) for root in roots);label='pid' if name=='pid_for_children' else name
  if any(re.match('^'+label+r':\[[1-9][0-9]{0,19}\]\Z',value) is None for value in pair) or pair[0]!=pair[1]:fail('namespace_mismatch')
  links.append((name,pair))
 return tuple(links),{'kind':kind,'names':names,'config_sha256':config,'config_namespaces':state}
def endpoint_chain(obj,path):
 def bounded(parts):
  result=[part for part in parts if part!='']
  if len(result)>64 or len(('/'+'/'.join(result)).encode('utf-8'))>4096:fail('endpoint_path')
  return result
 if type(path) is not str or not path.startswith('/') or '\0' in path:fail('endpoint_path')
 initial=path.split('/')
 if any(part in ('','.','..') for part in initial[1:]):fail('endpoint_path')
 pending=bounded(initial);resolved=[];observed=[];seen=set();links=0;steps=0
 while True:
  obj.files.check();steps+=1
  if steps>256:fail('endpoint_path')
  current='/' if not resolved else '/'+ '/'.join(resolved)
  metadata=meta(obj.fs.lstat(current));obj.private.setdefault('path_observations',[]).append((current,metadata))
  if stat.S_ISLNK(metadata[2]):
   if metadata[3]!=0 or links>=8 or (metadata[0],metadata[1]) in seen:fail('endpoint_metadata')
   seen.add((metadata[0],metadata[1]));links+=1;target=obj.link(current)
   if '\0' in target or target.endswith('/') and not pending:fail('endpoint_path')
   obj.files.check();after=meta(obj.fs.lstat(current));obj.private.setdefault('path_observations',[]).append((current,after))
   if after!=metadata:fail('identity_changed')
   observed.append((current,metadata,target))
   obj.private.setdefault('path_links',[]).append((current,metadata,target,after))
   parent=resolved[:-1];resolved=[] if target.startswith('/') else parent
   pending=bounded(target.split('/')+pending);bounded(resolved+pending);continue
  observed.append((current,metadata,None))
  if pending:
   if not stat.S_ISDIR(metadata[2]) or metadata[3]!=0 or metadata[2]&0o022:fail('endpoint_metadata')
   part=pending.pop(0)
   if part=='.':continue
   if part=='..':
    if not resolved:fail('endpoint_path')
    resolved.pop()
   else:resolved.append(part)
   bounded(resolved+pending);continue
  if not stat.S_ISSOCK(metadata[2]) or metadata[3]!=0 or metadata[2]&0o002:fail('endpoint_metadata')
  return tuple(observed)
'''


def _replace(source, old, new):
    if source.count(old)!=1:raise ValueError('legacy_fragment')
    return source.replace(old,new,1)


def _legacy():
    path=BASE/'host/wpa_daemon_identity_readonly.py'
    if any(p.is_symlink() for p in (path,)+tuple(path.parents)):raise ValueError('legacy_shape')
    before=path.stat()
    if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=262144:raise ValueError('legacy_shape')
    with path.open('rb') as handle:
        opened=os.fstat(handle.fileno());raw=handle.read(262145)
    after=path.stat()
    if any(getattr(before,k)!=getattr(opened,k) or getattr(before,k)!=getattr(after,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns')) or len(raw)!=before.st_size or hashlib.sha256(raw).hexdigest()!=LEGACY_PIN:raise ValueError('legacy_pin')
    module=types.ModuleType('pinned_wpa_identity_be59');module.__file__=str(path)
    exec(raw,module.__dict__)
    return module,raw.decode('utf-8')


def _adapt(legacy, raw):
    bools=legacy.BOOLS+('profile_complete',);counts=dict(legacy.COUNTS,namespace_count=8)
    reasons=legacy.REASONS+('namespace_profile','namespace_config')
    core=legacy.REMOTE_CORE
    old=r"""  opts=options(argv);ids=uid_gid(self.files.read(root+'/status',32768));ns=[]
  for name in ('mnt','net','pid','user'):
   pair=(self.link(root+'/ns/'+name),self.link('/proc/self/ns/'+name))
   if any(re.match('^'+name+r':\[[1-9][0-9]{0,19}\]\Z',v) is None for v in pair):fail('namespace_invalid')
   ns.append((name,pair))"""
    core=_replace(core,old,"  opts=options(argv);ids=uid_gid(self.files.read(root+'/status',32768));ns,profile=namespace_observe(self,actor)")
    core=_replace(core,"'namespaces':tuple(ns),'image_sha'","'namespaces':tuple(ns),'namespace_profile':profile,'image_sha'")
    core=_replace(core,"failure={'stage':'complete','class':'none','reason':'not_recorded','errno':0};trace=None","summary['namespace_profile']='not_recorded'\n  failure={'stage':'complete','class':'none','reason':'not_recorded','errno':0};trace=None")
    core=_replace(core,"summary['namespaces_equal']=all(pair[0]==pair[1] for unused,pair in first['namespaces'])","summary['profile_complete']=first['namespace_profile']==last['namespace_profile'] and all(pair[0]==pair[1] for unused,pair in first['namespaces'])\n   summary['namespace_profile']=first['namespace_profile']['kind'];summary['namespace_count']=len(first['namespaces'])\n   summary['namespaces_equal']=summary['profile_complete'] and summary['namespace_profile']=='full4_present'")
    core=_replace(core,"if not summary['namespaces_equal']:fail('namespace_mismatch')","if not summary['profile_complete']:fail('namespace_mismatch')")
    old_chain="""  row,path=candidates[0];chain=[];parts=path.split('/')
  if any(x in ('','.','..') for x in parts[1:]):fail('endpoint_path')
  for index in range(len(parts)):
   part='/' if index==0 else '/'.join(parts[:index+1]);s=self.fs.lstat(part);m=meta(s)
   self.private.setdefault('path_observations',[]).append((part,m))
   if index<len(parts)-1:
    if not stat.S_ISDIR(m[2]) or m[3]!=0 or m[2]&0o022:fail('endpoint_metadata')
   elif not stat.S_ISSOCK(m[2]) or m[3]!=0 or m[2]&0o002:fail('endpoint_metadata')
   chain.append((part,m))"""
    core=_replace(core,old_chain,"  row,path=candidates[0];chain=endpoint_chain(self,path)")
    projection=raw[raw.index('def _project(value):'):raw.index('\ndef _remote(')]
    projection=_replace(projection,"set(BOOLS)|set(COUNTS)","set(BOOLS)|set(COUNTS)|{'namespace_profile'}")
    projection=_replace(projection,"if summary['wlan_present'] and not summary['wlan_observed']:","if type(summary['namespace_profile']) is not str or summary['namespace_profile'] not in PROFILES:raise ValueError('profile_shape')\n    if summary['profile_complete'] and (summary['namespace_profile']=='not_recorded' or summary['namespace_count']<2 or summary['namespace_profile']=='namespaces_disabled_cgroup_mnt' and (summary['namespace_count']!=2 or summary['namespaces_equal']) or summary['namespace_profile']=='full4_present' and (summary['namespace_count']<4 or not summary['namespaces_equal'])):raise ValueError('profile_shape')\n    if summary['namespaces_equal'] and (not summary['profile_complete'] or summary['namespace_profile']!='full4_present'):raise ValueError('profile_shape')\n    if summary['wlan_present'] and not summary['wlan_observed']:")
    projection=_replace(projection,"'image_stable','namespaces_equal','endpoint_stable'","'image_stable','profile_complete','endpoint_stable'")
    projector=types.ModuleType('pinned_wpa_profile_projection');projector.__dict__.update(BOOLS=bools,COUNTS=counts,REASONS=reasons,STAGES=legacy.STAGES,CLASSES=legacy.CLASSES,PROFILES=PROFILES)
    exec(projection,projector.__dict__)
    return core,projector._project,bools,counts,reasons


def source_check():
    legacy,raw=_legacy();checks,source=legacy.source_check();core,project,bools,counts,reasons=_adapt(legacy,raw)
    prefix=source[:source.index(legacy.REMOTE_CORE)]
    prefix=_replace(prefix,'BOOLS='+repr(legacy.BOOLS),'BOOLS='+repr(bools))
    prefix=_replace(prefix,'COUNTS='+repr(legacy.COUNTS),'COUNTS='+repr(counts))
    prefix=_replace(prefix,'REASONS='+repr(legacy.REASONS),'REASONS='+repr(reasons))
    source=prefix+PROFILE_CODE+core+legacy.REMOTE_ENTRY
    tree=ast.parse(source,feature_version=(3,5))
    if any(isinstance(n,ast.Assert) for n in ast.walk(tree)) or len(source.encode('utf-8'))>legacy.MAX_SOURCE or max(map(len,source.splitlines()))>2048:raise ValueError('source_budget')
    checks=dict(checks,checker_sha256=hashlib.sha256(legacy._read(Path(__file__).absolute())).hexdigest(),legacy_checker_sha256=LEGACY_PIN,source_version=SOURCE_VERSION)
    return checks,source,legacy,project


def run_readonly(expected,_adb_factory=None,_output=None):
    checks,source,legacy,project=source_check()
    if type(expected) is not str or re.fullmatch('[0-9a-f]{64}',expected) is None or expected!=checks['checker_sha256']:raise ValueError('reviewed_pin')
    if _EXECUTIONS:raise ValueError('already_attempted')
    execution={'source':source,'legacy':legacy,'project':project,'adb':None};_EXECUTIONS.append(execution)
    out=Path(_output) if _output is not None else ROOT/'logs'/('MtaP011-WpaDaemonProfileReadOnly-'+datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')+'-'+os.urandom(4).hex())
    out.mkdir(parents=True,exist_ok=False)
    report=dict(checks,evidence='P011_READONLY_WPA_PROFILE_FACTS',**{'pass':False,'target_selected':False,'device_command_attempted':False,'device_reply_confirmed':False,'device_writes':False,'rf_operations':False,'status_sent':False,'socket_created':False,'daemon_manifest_authenticated':False,'namespace_authenticated':False,'network_restoration':'NOT_EVALUATED','receive_available':False,'send_available':False,'selector_raw_captured':False})
    try:
        if _adb_factory is None:
            helper=types.ModuleType('p011_pinned_wpa_adb');helper.__file__=str(BASE/'host/device_probe.py')
            exec(legacy._read(BASE/'host/device_probe.py',legacy.ADB_PIN),helper.__dict__);_adb_factory=helper.Adb
        adb=_adb_factory(out/'private-raw');execution['adb']=adb;report['target_selected']=True;report['device_command_attempted']=True
        value=legacy._remote(adb,source,execution);report['device_reply_confirmed']=True;facts=project(value)
        report.update(facts);report['pass']=report.pop('pass_value')
    except Exception as e:
        execution['first_error']=e;report['error_class']='os_error' if isinstance(e,OSError) else 'value_error' if isinstance(e,ValueError) else 'runtime_error' if isinstance(e,RuntimeError) else 'unexpected'
        report['errno']=getattr(e,'errno',0) if type(getattr(e,'errno',0)) is int and 0<=getattr(e,'errno',0)<=4095 else 0
    (out/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (out/'README.txt').write_text('WPA profile source-v2: actual bounded root-owned symlink path evidence.\nPrior source3901 actual FAIL (203 own+12 ProcReader closed) remains unchanged.\nNo STATUS/socket/RF/network/pending/staging/repair; no daemon/reply/namespace authentication.\nActual link targets/metadata/resolved chain, namespaces/config/identity/traceback stay private raw.\nprofile_complete is not all-four namespaces_equal or production admission.\nOnly original known FD closures; selector enumeration raw not independently captured.\n',encoding='utf-8')
    with zipfile.ZipFile(out.with_suffix('.sanitized.zip'),'x',zipfile.ZIP_DEFLATED) as bundle:
        for name in ('result.json','README.txt'):bundle.write(out/name,name)
    return report,out


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);modes=parser.add_mutually_exclusive_group()
    modes.add_argument('--source-check-only',action='store_true');modes.add_argument('--execute-readonly',action='store_true')
    parser.add_argument('--expected-checker-sha256');args=parser.parse_args(argv)
    if args.execute_readonly!=(args.expected_checker_sha256 is not None):parser.error('Explicit read-only execution and exact checker SHA required together')
    try:
        report=run_readonly(args.expected_checker_sha256)[0] if args.execute_readonly else source_check()[0]
        print(json.dumps(report,indent=2));return 0 if report.get('source_check_pass') and not args.execute_readonly or report.get('pass') else 1
    except Exception:
        print(json.dumps({'pass':False,'error_class':'source_or_output','device_command_attempted':'NOT_RECORDED','device_reply_confirmed':False}));return 1


if __name__=='__main__':sys.exit(main())
