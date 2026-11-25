"""ROOT-reviewed fixed candidate permission normalization, not a radio trial.

Import has no device action. The only CLI mode is --normalize-reviewed; all
sixteen descriptors are verified before the first fchmod. No chown/path chmod,
rollback, candidate replacement, RF, IP, recovery or automatic retry exists.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import sys
import zipfile

from device_probe import Adb,ROOT
from device_p2p import _data
import device_candidate_permissions_readonly as permission_reference
import device_prior_journal_readonly as previous
import device_p2p_v6diag as reference


PERMISSIONS_CHECKER_SHA256="ca2ab521dd6acc12a5f9e0ff30914917c36b2992b31393d09178768f60d1c1fa"
CANDIDATES=permission_reference.CANDIDATES
RELATIVES=permission_reference.RELATIVES
STAGES=frozenset(("not_recorded","directory_safety","file_open","prevalidation","candidate_contents",
                 "before_fchmod","fchmod","readback","close","complete"))
REASONS=frozenset(("not_recorded","file_not_regular","foreign_owner","file_link_count","unknown_file_mode",
    "file_identity_changed","file_pin_mismatch","candidate_contents_invalid","duplicate_file_identity",
    "readonly_permission_deadline","target_mode_mismatch","unmapped_value_error","os_error","unexpected_exception"))
CLASSES=frozenset(("none","value_error","os_error","unexpected_exception"))
ROW_BOOL_FIELDS=frozenset(("prevalidated","fchmod_attempted","changed","mode_observed","readback_confirmed","identity_unchanged","hash_unchanged"))
ROW_FIELDS=ROW_BOOL_FIELDS|{"candidate","relative","old_mode","new_mode","target_mode"}
COUNT_FIELDS=frozenset(("file_count","prevalidated_count","fchmod_attempt_count","partial_change_count","readback_count",
                       "fd_open_count","fd_close_attempt_count","fd_closed_count","fd_close_failed_count"))
BOOL_FIELDS=frozenset(("complete","all_prevalidated_before_writes","change_count_complete","descriptors_all_closed"))
RESULT_FIELDS=COUNT_FIELDS|BOOL_FIELDS|{"files","first_failure_stage","first_failure_candidate","first_failure_relative","reason","error_class","errno"}


BODY=r'''
end=time.monotonic()+25;stage='directory_safety';alias='not_recorded';relative='not_recorded';fds=[]
result={'complete':False,'all_prevalidated_before_writes':False,'change_count_complete':True,'descriptors_all_closed':False,
 'files':[],'file_count':0,'prevalidated_count':0,'fchmod_attempt_count':0,'partial_change_count':0,'readback_count':0,
 'fd_open_count':0,'fd_close_attempt_count':0,'fd_closed_count':0,'fd_close_failed_count':0,
 'first_failure_stage':'not_recorded','first_failure_candidate':'not_recorded','first_failure_relative':'not_recorded',
 'reason':'not_recorded','error_class':'none','errno':0}
def deadline():
 if time.monotonic()>=end:raise ValueError('readonly_permission_deadline')
def full_identity(value):
 return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
def stable_identity(value):
 return (value.st_dev,value.st_ino,stat.S_IFMT(value.st_mode),value.st_uid,value.st_gid,value.st_nlink,value.st_size,value.st_mtime_ns)
def verify_hash(fd,size,pin):
 deadline();os.lseek(fd,0,os.SEEK_SET);digestvalue=hashlib.sha256();count=0
 while count<size:
  deadline();blob=os.read(fd,min(65536,size-count))
  if not blob:break
  count+=len(blob);digestvalue.update(blob)
 deadline()
 if count!=size or os.read(fd,1) or digestvalue.hexdigest()!=pin:raise ValueError('file_pin_mismatch')
def failure(error,failed_stage,failed_alias,failed_relative):
 if result['first_failure_stage']!='not_recorded':return
 result['first_failure_stage']=failed_stage;result['first_failure_candidate']=failed_alias;result['first_failure_relative']=failed_relative
 if isinstance(error,OSError):
  result['error_class']='os_error';result['reason']='os_error';number=error.errno
  result['errno']=number if type(number) is int and 1<=number<=4095 else 0
 elif isinstance(error,ValueError):
  result['error_class']='value_error';token=error.args[0] if len(error.args)==1 and type(error.args[0]) is str else None
  result['reason']=token if token in VALUE_REASONS else 'unmapped_value_error'
 else:result['error_class']='unexpected_exception';result['reason']='unexpected_exception'
try:
 identities=set()
 for alias in ('v5','v6'):
  relative='not_recorded';stage='directory_safety';deadline();known=CANDIDATES[alias]
  base=AREA+'/candidates/mta-01-'+known['identity']
  private_folder(base);private_folder(base+'/runtime');private_folder(base+'/native')
  for relative in sorted(known['pins']):
   stage='file_open';deadline();path=base+'/'+relative;before=os.lstat(path)
   if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):raise ValueError('file_not_regular')
   if before.st_uid!=os.geteuid():raise ValueError('foreign_owner')
   if before.st_nlink!=1:raise ValueError('file_link_count')
   native=relative.startswith('native/');target=0o500 if native else 0o400
   if stat.S_IMODE(before.st_mode) not in ((0o700,0o500) if native else (0o666,0o400)):raise ValueError('unknown_file_mode')
   key=(before.st_dev,before.st_ino)
   if key in identities:raise ValueError('duplicate_file_identity')
   identities.add(key);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
   row={'candidate':alias,'relative':relative,'old_mode':stat.S_IMODE(before.st_mode),'new_mode':stat.S_IMODE(before.st_mode),'target_mode':target,
    'prevalidated':False,'fchmod_attempted':False,'changed':False,'mode_observed':True,'readback_confirmed':False,'identity_unchanged':False,'hash_unchanged':False}
   entry={'fd':fd,'path':path,'before':before,'size':known['sizes'][relative],'pin':known['pins'][relative],'row':row}
   fds.append(entry);result['fd_open_count']+=1;result['files'].append(row);os.set_inheritable(fd,False)
   stage='prevalidation';deadline()
   if full_identity(os.fstat(fd))!=full_identity(before):raise ValueError('file_identity_changed')
   if before.st_size!=entry['size']:raise ValueError('file_pin_mismatch')
   verify_hash(fd,entry['size'],entry['pin'])
   if full_identity(os.fstat(fd))!=full_identity(before) or full_identity(os.lstat(path))!=full_identity(before):raise ValueError('file_identity_changed')
   row['prevalidated']=True;result['prevalidated_count']+=1
  relative='not_recorded';stage='candidate_contents';deadline();observed=set()
  for folder,dirs,files in os.walk(base,followlinks=False):
   deadline();owned_directory(folder)
   if len(dirs)+len(files)>32 or any(os.path.islink(folder+'/'+name) for name in dirs):raise ValueError('candidate_contents_invalid')
   observed.update(os.path.relpath(folder+'/'+name,base).replace(os.sep,'/') for name in files)
   if len(observed)>8:raise ValueError('candidate_contents_invalid')
  if observed!=set(known['pins']):raise ValueError('candidate_contents_invalid')
 if len(fds)!=16 or result['prevalidated_count']!=16:raise ValueError('candidate_contents_invalid')
 result['all_prevalidated_before_writes']=True
 for entry in fds:
  row=entry['row'];alias=row['candidate'];relative=row['relative'];fd=entry['fd'];before=entry['before'];path=entry['path']
  stage='before_fchmod';deadline()
  if full_identity(os.fstat(fd))!=full_identity(before) or full_identity(os.lstat(path))!=full_identity(before):raise ValueError('file_identity_changed')
  if row['old_mode']!=row['target_mode']:
   stage='fchmod';deadline();row['fchmod_attempted']=True;result['fchmod_attempt_count']+=1
   # Observe a failed call too; never infer that a raised syscall changed none.
   try:os.fchmod(fd,row['target_mode'])
   except Exception:
    try:
     actual=os.fstat(fd);row['new_mode']=actual.st_mode&0o777;row['mode_observed']=True
     row['changed']=row['new_mode']!=row['old_mode']
    except Exception:row['mode_observed']=False;result['change_count_complete']=False
    raise
   row['changed']=True;row['new_mode']=row['target_mode'];row['mode_observed']=False
  stage='readback';deadline();actual=os.fstat(fd)
  row['new_mode']=actual.st_mode&0o777;row['mode_observed']=True;row['changed']=row['new_mode']!=row['old_mode']
  if stable_identity(actual)!=stable_identity(before) or full_identity(os.lstat(path))!=full_identity(actual):raise ValueError('file_identity_changed')
  row['identity_unchanged']=True
  if stat.S_IMODE(actual.st_mode)!=row['target_mode']:raise ValueError('target_mode_mismatch')
  verify_hash(fd,entry['size'],entry['pin'])
  if full_identity(os.fstat(fd))!=full_identity(actual) or full_identity(os.lstat(path))!=full_identity(actual):raise ValueError('file_identity_changed')
  row['hash_unchanged']=True;row['readback_confirmed']=True;result['readback_count']+=1
 stage='complete';result['complete']=True
except Exception as error:
 failure(error,stage,alias,relative)
finally:
 for entry in fds:
  # If failure intervened after a successful fchmod, make one final best-effort
  # observation without another permission write. Unknown stays explicit.
  row=entry['row']
  if row['fchmod_attempted'] and not row['mode_observed']:
   try:
    actual=os.fstat(entry['fd']);row['new_mode']=actual.st_mode&0o777;row['mode_observed']=True
    row['changed']=row['new_mode']!=row['old_mode']
   except Exception:result['change_count_complete']=False
  result['fd_close_attempt_count']+=1
  try:os.close(entry['fd']);result['fd_closed_count']+=1
  except Exception as error:
   result['fd_close_failed_count']+=1;result['complete']=False;failure(error,'close',row['candidate'],row['relative'])
 result['descriptors_all_closed']=result['fd_closed_count']==len(fds) and result['fd_close_failed_count']==0
 result['partial_change_count']=sum(row['changed'] for row in result['files'])
 result['file_count']=len(result['files'])
print('RESULT='+repr(result))
'''


def validate_result(value):
    if type(value) is not dict or set(value)!=RESULT_FIELDS or any(type(value[key]) is not bool for key in BOOL_FIELDS):raise ValueError("Normalize result schema")
    if any(type(value[key]) is not int or not 0<=value[key]<=16 for key in COUNT_FIELDS):raise ValueError("Normalize result counts")
    if (type(value['files']) is not list or len(value['files'])!=value['file_count'] or type(value['first_failure_stage']) is not str or value['first_failure_stage'] not in STAGES or
        value['first_failure_candidate'] not in ('not_recorded','v5','v6') or type(value['first_failure_relative']) is not str or value['first_failure_relative'] not in RELATIVES|{'not_recorded'} or
        type(value['reason']) is not str or value['reason'] not in REASONS or type(value['error_class']) is not str or value['error_class'] not in CLASSES or type(value['errno']) is not int or not 0<=value['errno']<=4095):raise ValueError("Normalize fixed failure schema")
    expected=[(alias,relative) for alias in ('v5','v6') for relative in sorted(RELATIVES)]
    for index,row in enumerate(value['files']):
        if (type(row) is not dict or set(row)!=ROW_FIELDS or any(type(row[key]) is not bool for key in ROW_BOOL_FIELDS) or
            type(row['candidate']) is not str or type(row['relative']) is not str or (row['candidate'],row['relative'])!=expected[index] or
            any(type(row[key]) is not int or not 0<=row[key]<=0o777 for key in ('old_mode','new_mode','target_mode')) or
            row['target_mode']!=(0o500 if row['relative'].startswith('native/') else 0o400) or
            row['old_mode'] not in ((0o700,0o500) if row['relative'].startswith('native/') else (0o666,0o400))):raise ValueError("Normalize file row schema")
        if (row['fchmod_attempted'] and not value['all_prevalidated_before_writes'] or row['readback_confirmed'] and
            (not row['prevalidated'] or not row['mode_observed'] or not row['identity_unchanged'] or not row['hash_unchanged'] or row['new_mode']!=row['target_mode']) or
            row['mode_observed'] and row['changed']!=(row['new_mode']!=row['old_mode'])):raise ValueError("Normalize row evidence consistency")
    if (value['prevalidated_count']!=sum(row['prevalidated'] for row in value['files']) or value['fchmod_attempt_count']!=sum(row['fchmod_attempted'] for row in value['files']) or
        value['readback_count']!=sum(row['readback_confirmed'] for row in value['files']) or value['partial_change_count']!=sum(row['changed'] for row in value['files']) or
        value['fd_open_count']!=value['file_count'] or value['fd_close_attempt_count']!=value['fd_open_count'] or value['fd_closed_count']+value['fd_close_failed_count']!=value['fd_open_count'] or
        value['descriptors_all_closed']!=(value['fd_close_failed_count']==0 and value['fd_closed_count']==value['fd_open_count']) or
        value['all_prevalidated_before_writes'] and value['prevalidated_count']!=16 or
        value['change_count_complete'] and any(row['fchmod_attempted'] and not row['mode_observed'] for row in value['files'])):raise ValueError("Normalize summary consistency")
    if value['complete'] and (value['readback_count']!=16 or not value['all_prevalidated_before_writes'] or not value['descriptors_all_closed'] or
        not value['change_count_complete'] or value['first_failure_stage']!='not_recorded' or value['reason']!='not_recorded' or value['error_class']!='none' or value['errno']!=0):raise ValueError("Normalize completion evidence")
    return value


def verify_reference():
    if hashlib.sha256(_data(Path(permission_reference.__file__),previous.MAX_SOURCE_BYTES)).hexdigest()!=PERMISSIONS_CHECKER_SHA256:raise ValueError("Permission checker reference changed")
    return permission_reference.verify_reference()


def source(safety):
    body=reference.READ_HELPERS+'\nCANDIDATES='+repr(CANDIDATES)+'\nVALUE_REASONS='+repr(tuple(sorted(REASONS-{'not_recorded','unmapped_value_error','os_error','unexpected_exception'})))+'\n'+BODY
    body="if digest("+repr(previous.TARGET+'/SOURCE.sha256')+")!="+repr(permission_reference.V6_MANIFEST)+":raise ValueError('readonly_manifest_pin')\n"+body
    program=reference.probe_source(previous.TARGET,safety,body);ast.parse(program,feature_version=(3,5))
    if len(program.encode('utf-8'))>previous.MAX_SOURCE_BYTES:raise ValueError("Normalize source limit")
    return program


def save_public(report,out):
    (out/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'README.txt').write_text("Explicit reviewed FIXED candidate permission changes: manifest/runtime0400; native0500.\n"
        "All sixteen O_RDONLY|O_NOFOLLOW descriptors validated before first fchmod. No path chmod/chown/rollback/global services/RF/IP/new trial/retry.\n"
        "First failure and partial known/unknown changes remain truthful; every opened FD receives its own close attempt.\n"
        "PASS is complete permission readback plus unchanged independent stock/network, NOT prior admission/GO/IP/phone transfer.\n"
        "Only result/README public; original raw stdout/stderr and host/remote exit evidence remain private.\n",encoding='utf-8')
    archive=Path(str(out)+'.sanitized.zip')
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as bundle:
        for name in ('result.json','README.txt'):bundle.write(out/name,name)
    return archive


def run_normalize(output=None):
    safety=verify_reference();baseline=previous.source(safety);program=source(safety)
    stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4)
    out=Path(output) if output else ROOT/'logs'/('MtaP011-CandidatePermissionsNormalize-'+stamp);out.mkdir(parents=True,exist_ok=False)
    report={'evidence_level':'P011_FIXED_CANDIDATE_PERMISSION_NORMALIZATION','pass':False,'normalization_complete':False,
        'checker_sha256':hashlib.sha256(_data(Path(__file__),previous.MAX_SOURCE_BYTES)).hexdigest(),'permission_write_requested':True,
        'radio_operations':False,'network_configuration':False,'candidate_staged':False,'chown_requested':False,'rollback_invoked':False,
        'recovery_invoked':False,'retry_invoked':False,'send_available':False,'ip_installation':'NOT_TESTED','phone_interop':'NOT_TESTED',
        'remote_statuses':{},'next_step':'REVIEW_PERMISSION_READBACK_NO_AUTO_TRIAL_OR_RECOVER'}
    adb=None;before=after=diagnostic=None;stage='target'
    try:
        adb=Adb(out/'private-raw');stage='before';before=previous.remote(adb,'before-normalize-reviewed',baseline,report['remote_statuses'])
        if not reference.preflight_ok(before):raise ValueError('Normalize preflight')
        stage='permission_normalize';report['permission_program_invoked']=True
        diagnostic=validate_result(previous.remote(adb,'fixed-permission-normalize-reviewed',program,report['remote_statuses']));report['normalization']=diagnostic
    except Exception:report['host_or_parse_error']=True;report['error_stage']=stage
    finally:
        if adb is not None:
            try:after=previous.remote(adb,'after-normalize-reviewed',baseline,report['remote_statuses'])
            except Exception:report['after_check_failed']=True
        gates={};reference.add_independent_gates(gates,before,after,None)
        fields=('stock_independent_unchanged','wifi_state_fingerprint_unchanged','station_state_digest_unchanged','frequency_unchanged','route_digest_unchanged',
            'full_ipv4_addresses_unchanged','full_ipv4_routes_unchanged','full_ipv4_rules_unchanged','full_ipv4_readback_unchanged','full_ipv6_readback_unchanged',
            'ipv6_address_digest_unchanged','ipv6_route_digest_unchanged','same_boot','network_processes_unchanged','interface_identities_unchanged','wifi_completed_after',
            'no_p2p_interfaces_after','no_project_mta_interfaces_after','no_private_wpa_processes_after','no_project_trial_actors_after','global_pending_clear_independent')
        report.update({field:gates[field] for field in fields});report.setdefault('permission_program_invoked',False)
        report['normalization_complete']=bool(diagnostic and diagnostic['complete'] and all(report[field] is True for field in fields) and
            not report.get('host_or_parse_error') and not report.get('after_check_failed'));report['pass']=report['normalization_complete']
    return report,out,save_public(report,out)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--normalize-reviewed',action='store_true',required=True);parser.add_argument('--output',type=Path)
    args=parser.parse_args();report,out,archive=run_normalize(args.output)
    print(json.dumps(report,ensure_ascii=False,indent=2));print('RESULT_DIR='+str(out));print('RESULT_ZIP='+str(archive))
    return 0 if report['normalization_complete'] else 1


if __name__=='__main__':sys.exit(main())
