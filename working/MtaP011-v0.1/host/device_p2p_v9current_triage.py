"""Fixed current V9 observation only. Import/tests are HOST-only.

No locks, staging, chmod, RF, address writes, stop or recovery. A complete
observation is not restoration/absence/write authorization or Wi-Fi readiness.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import sys

from device_probe import Adb, ROOT
from device_p2p import _data
import device_p2p_v9bounded as bounded

RUN = bounded.AREA + "/sessions/mta-p2p-v2-20261001-084811-e064eae6"
REFERENCE_SHA256 = "20e816a946ff4a4470db61134ca38f22f342e3cdac55711b8ac2e0dc52b75fea"
ACTOR_STAGES = frozenset(("not_recorded", "list", "count", "cmdline", "stat", "absence", "match", "done"))
ACTOR_REASONS = frozenset(("not_recorded", "clear", "actor_present", "proc_count_limit", "list_read_error",
    "cmdline_read_errno", "cmdline_byte_limit", "cmdline_truncated", "cmdline_type", "stat_read_errno",
    "stat_byte_limit", "stat_shape_invalid", "stat_flags_invalid", "stat_identity_invalid", "empty_user_zombie", "empty_unknown",
    "disappeared_not_proven", "absence_read_errno", "deadline", "unexpected_read_error"))
COUNT_KEYS = frozenset(("numeric_seen", "examined", "disappeared_confirmed", "empty_kernel", "empty_user_zombie",
    "empty_unknown", "truncated", "read_errno", "matched_project"))
JOURNAL_STAGES = frozenset(bounded.reader.old.STAGES) | {"not_recorded"}
IP_STAGES = frozenset(bounded.reader.old.IP_STAGES) | {"not_recorded"}
READ_REASONS = frozenset(("not_recorded", "complete", "schema_or_read_error", "read_errno", "deadline"))
OWNED_REASONS = frozenset(("not_recorded", "absent", "exact", "collision", "type_changed", "sysfs_absent",
    "journal_unavailable", "schema_or_read_error", "read_errno", "deadline"))
FATAL_REASONS = frozenset(("none", "reference", "netlink_constructor", "deadline", "unexpected_read_error", "descriptor_close"))

# READ_HELPERS are fixed reviewed read-only definitions, not a runtime runner.
BODY = r'''
import mta_send_wifi as wifi
end=time.monotonic()+25;connection=None;retained_socket=None;constructed=False
value={'check_complete':False,'snapshots_equal':False,'netlink_socket_closed':False,
 'fatal_reason':'none','observations':[],'readonly_only':True,
 'network_mutations':False,'device_writes':False,'authorization_or_lock_held':False}
def deadline():
 if time.monotonic()>=end:raise TimeoutError('triage_deadline')
def errno_number(error):
 number=getattr(error,'errno',0)
 return number if type(number) is int and 0<=number<=4095 else 0
def error_reason(error):
 return 'deadline' if isinstance(error,TimeoutError) else 'read_errno' if isinstance(error,OSError) else 'schema_or_read_error'
def actor_scan():
 result={'complete':False,'clear':False,'reason':'not_recorded','stage':'not_recorded','errno':0,
  'count_valid':False,'zombie_tasks_recorded':False,'zombie_task_count':None,'zombie_task_errno':0,'counts':dict((key,0) for key in
  ('numeric_seen','examined','disappeared_confirmed','empty_kernel','empty_user_zombie','empty_unknown','truncated','read_errno','matched_project'))}
 private=[];counts=result['counts'];failure='unexpected_read_error'
 try:
  result['stage']='list';failure='list_read_error';deadline();names=os.listdir('/proc')
  result['stage']='count';failure='proc_count_limit';numeric=[token for token in names if token.isdigit()]
  if len(numeric)>4095:raise ValueError('triage_proc_limit')
  counts['numeric_seen']=len(numeric);result['count_valid']=True
  if len(numeric)>512:raise ValueError('triage_proc_limit')
  for token in numeric:
   deadline()
   if int(token)==os.getpid():continue
   counts['examined']+=1;result['stage']='cmdline';failure='cmdline_byte_limit'
   try:blob=bounded('/proc/'+token+'/cmdline',65536)
   except OSError as error:
    if error.errno not in (2,3):failure='cmdline_read_errno';raise
    result['stage']='absence';failure='absence_read_errno';deadline()
    if not process_absent({'pid':int(token)}):failure='disappeared_not_proven';raise ValueError('triage_absence_unknown')
    counts['disappeared_confirmed']+=1;private.append((token,'disappeared'));continue
   failure='cmdline_type'
   if type(blob) is not bytes:raise ValueError('triage_cmdline_type')
   failure='cmdline_truncated'
   if len(blob)>65536 or blob and blob[-1:]!=b'\0':counts['truncated']+=1;raise ValueError('triage_cmdline_truncated')
   private.append((token,hashbytes(blob)))
   if not blob:
    result['stage']='stat';failure='stat_byte_limit';deadline()
    try:rawstat=bounded('/proc/'+token+'/stat',32768)
    except OSError as error:
     if error.errno not in (2,3):failure='stat_read_errno';raise
     result['stage']='absence';failure='absence_read_errno';deadline()
     if not process_absent({'pid':int(token)}):failure='disappeared_not_proven';raise ValueError('triage_absence_unknown')
     counts['disappeared_confirmed']+=1;private.append((token,'disappeared_stat'));continue
    failure='stat_shape_invalid';tail=rawstat.rsplit(b')',1)
    if len(tail)!=2 or len(tail[1].split())<20:raise ValueError('triage_stat_shape')
    prefix=tail[0].split(b' (',1);fields=tail[1].split();flag=fields[6];failure='stat_flags_invalid'
    if not flag.isdigit() or len(flag)>10 or not 0<=int(flag)<=0xffffffff:raise ValueError('triage_stat_flags')
    failure='stat_identity_invalid';start=fields[19]
    if (len(prefix)!=2 or not prefix[0].isdigit() or len(prefix[0])>10 or not 0<int(prefix[0])<=0x7fffffff or
     int(prefix[0])!=int(token) or not 1<=len(prefix[1])<=64 or b'\0' in prefix[1] or
     len(fields[0])!=1 or fields[0] not in tuple(bytes([letter]) for letter in b'RSDTtXZxKWPI') or
     not start.isdigit() or len(start)>20 or not 0<=int(start)<=0xffffffffffffffff):raise ValueError('triage_stat_identity')
    # CPU ticks and other dynamic stat counters are not identity/equality facts.
    private.append((int(prefix[0]),int(start),prefix[1],fields[0],int(flag)))
    if int(flag)&0x00200000:counts['empty_kernel']+=1;continue
    if fields[0]==b'Z':
     counts['empty_user_zombie']+=1;failure='empty_user_zombie'
     try:
      deadline();tasks=os.listdir('/proc/'+token+'/task')
      if not 1<=len(tasks)<=512 or any(not task.isdigit() for task in tasks):raise ValueError('triage_task_shape')
      result['zombie_task_count']=len(tasks);result['zombie_tasks_recorded']=True
     except BaseException as error:result['zombie_task_errno']=errno_number(error)
    else:counts['empty_unknown']+=1;failure='empty_unknown'
    raise ValueError('triage_empty_actor_opaque')
   result['stage']='match';failure='unexpected_read_error';args=blob.split(b'\0')
   matched=(b'mta-prior-readonly' in args or
    any(item.startswith((AREA+'/candidates/').encode('ascii')) and item.endswith(b'/runtime/mta_send_wifi.py') for item in args)
    and (b'--trial' in args or b'--recover' in args) or
    any(item.startswith((AREA+'/candidates/').encode('ascii')) and item.endswith(b'/native/mta-wpa-supplicant') for item in args))
   if matched:
    counts['matched_project']+=1;result.update(complete=True,reason='actor_present');return result,private
  result.update(complete=True,clear=True,reason='clear',stage='done')
 except TimeoutError:result['reason']='deadline'
 except OSError as error:
  counts['read_errno']+=1;result['errno']=errno_number(error);result['reason']=failure
 except BaseException:result['reason']=failure
 return result,private
def journal_observation():
 result={'complete':False,'reason':'not_recorded','errno':0,'same_boot':False,
  'stage':'not_recorded','ip_stage':'not_recorded','owned_recorded':False,'process_absent':False}
 record=None;boot=None
 try:
  deadline();private_folder(RUN);record=private_record(RUN+'/p2p-lease.json');validate_journal3(record)
  wifi._journal_envelope(record);boot=bounded('/proc/sys/kernel/random/boot_id',128).decode('ascii').strip()
  if not boot:raise ValueError('triage_boot_unknown')
  result['same_boot']=record['baseline']['boot_id']==boot;result['stage']=record['stage']
  result['ip_stage']='none' if record['ip'] is None else record['ip']['stage']
  result['owned_recorded']=record['owned'] is not None;deadline();result['process_absent']=process_absent(record['process'])
  result.update(complete=True,reason='complete')
 except BaseException as error:result['reason']=error_reason(error);result['errno']=errno_number(error);record=None
 return result,record,boot
def pending_observation(record,boot):
 result={'complete':False,'reason':'not_recorded','errno':0,'present':False,'safe':False,'valid':False,
  'lock_safe':False,'exact_run':False,'same_boot':False};saved=None
 try:
  deadline();observed=pending_readonly()
  result.update((key,observed[key]) for key in ('present','safe','valid','lock_safe'))
  if observed['present']:
   saved=private_record(DEVICE_PENDING)
   result['exact_run']=saved.get('journal')==RUN+'/p2p-lease.json'
   result['same_boot']=bool(boot is not None and saved.get('boot_id')==boot)
  if not observed['safe'] or not observed['valid'] or not observed['lock_safe']:raise ValueError('triage_pending_schema')
  result.update(complete=True,reason='complete')
 except BaseException as error:result['reason']=error_reason(error);result['errno']=errno_number(error)
 return result,saved
def owned_observation(record):
 result={'complete':False,'reason':'not_recorded','errno':0,'netlink_recorded':False,'row_count':0,'match_count':0,
  'name_present':False,'ifindex_present':False,'wdev_present':False,'phy_present':False,
  'exact_origin':False,'collision':False,'iftype':None,'sysfs_recorded':False,'sysfs_present':False,
  'sysfs_identity_match':False,'flags_recorded':False,'flags_up':False};private={}
 try:
  deadline();rows=connection.interfaces()
  if type(rows) is not list or len(rows)>4095:raise ValueError('triage_interface_limit')
  for row in rows:
   if type(row) is not dict or set(row)-{'name','ifindex','wdev','phy','iftype'}:raise ValueError('triage_interface_schema')
   if any(type(row.get(key)) is not int for key in ('wdev','phy','iftype')) or not 0<=row['iftype']<=12:
    raise ValueError('triage_interface_schema')
   if 'ifindex' in row and (type(row['ifindex']) is not int or not 0<row['ifindex']<=0x7fffffff):raise ValueError('triage_ifindex')
  result['netlink_recorded']=True;result['row_count']=len(rows);private['rows']=rows
  if record is None or record['owned'] is None:result['reason']='journal_unavailable';return result,private
  owned=record['owned'];keys=('name','ifindex','wdev','phy')
  for key in keys:result[key+'_present']=any(row.get(key)==owned[key] for row in rows)
  matched=[row for row in rows if any(row.get(key)==owned[key] for key in ('name','ifindex','wdev'))]
  result['match_count']=len(matched);result['exact_origin']=len(matched)==1 and all(matched[0].get(key)==owned[key] for key in keys)
  result['collision']=bool(matched and not result['exact_origin'])
  if len(matched)==1:result['iftype']=matched[0]['iftype']
  result['reason']='collision' if result['collision'] else 'exact' if result['exact_origin'] else 'absent'
  if result['exact_origin'] and result['iftype'] not in (2,8,9):result['reason']='type_changed'
  root='/sys/class/net/'+owned['name'];deadline()
  try:os.lstat(root)
  except OSError as error:
   if error.errno!=2:raise
   result['sysfs_recorded']=True
   if result['exact_origin']:result['reason']='sysfs_absent'
   result['complete']=True;return result,private
  result['sysfs_recorded']=True;result['sysfs_present']=True
  index=bounded(root+'/ifindex',16).decode('ascii').strip();flags=bounded(root+'/flags',33).decode('ascii').strip()
  private.update(index=index,flags=flags)
  if not re.match(r'^[0-9]{1,10}\Z',index) or not re.match(r'^0x[0-9a-fA-F]{1,8}\Z',flags):raise ValueError('triage_sysfs_shape')
  result['sysfs_identity_match']=int(index)==owned['ifindex'];result['flags_recorded']=True;result['flags_up']=bool(int(flags,16)&1)
  result['complete']=True
 except BaseException as error:result['reason']=error_reason(error);result['errno']=errno_number(error)
 return result,private
def observe():
 journal,record,boot=journal_observation();pending,saved=pending_observation(record,boot)
 actors,private_actors=actor_scan();owned,private_owned=owned_observation(record)
 return ({'journal':journal,'pending':pending,'actors':actors,'owned':owned},
  {'journal':record,'pending':saved,'boot':boot,'actors':private_actors,'owned':private_owned})
try:
 value['fatal_reason']='reference'
 if digest(TARGET+'/SOURCE.sha256')!=MANIFEST_SHA256:raise ValueError('triage_manifest')
 value['fatal_reason']='netlink_constructor';deadline();connection=ReadWriteNetlink.__new__(ReadWriteNetlink)
 ReadWriteNetlink.__init__(connection);retained_socket=connection.sock
 if type(retained_socket.fileno()) is not int or retained_socket.fileno()<0:raise ValueError('triage_socket_identity')
 constructed=True;value['fatal_reason']='none';pairs=[]
 for unused in range(2):
  observation,private=observe();value['observations'].append(observation);pairs.append(private)
 value['snapshots_equal']=value['observations'][0]==value['observations'][1] and pairs[0]==pairs[1]
except TimeoutError:value['fatal_reason']='deadline'
except BaseException:
 if value['fatal_reason']=='none':value['fatal_reason']='unexpected_read_error'
finally:
 closed=constructed
 if connection is not None:
  if retained_socket is None:retained_socket=getattr(connection,'sock',None)
  try:connection.close()
  except BaseException:closed=False
 try:closed=bool(closed and retained_socket is not None and type(retained_socket.fileno()) is int and retained_socket.fileno()==-1)
 except BaseException:closed=False
 value['netlink_socket_closed']=closed
 if not closed and value['fatal_reason']=='none':value['fatal_reason']='descriptor_close'
 value['check_complete']=bool(value['fatal_reason']=='none' and closed and len(value['observations'])==2 and
  value['snapshots_equal'] and all(row[key]['complete'] is True for row in value['observations'] for key in ('journal','pending','actors','owned')))
print('RESULT='+repr(value))
'''


def _shape(value, fields, booleans):
    if type(value) is not dict or set(value)!=set(fields) or any(type(value[key]) is not bool for key in booleans):
        raise ValueError("Current triage schema")


def _errno(value):
    if type(value) is not int or not 0<=value<=4095:raise ValueError("Current triage errno")


def validate_result(value):
    top=("check_complete","snapshots_equal","netlink_socket_closed","fatal_reason","observations",
         "readonly_only","network_mutations","device_writes","authorization_or_lock_held")
    flags=set(top)-{"fatal_reason","observations"};_shape(value,top,flags)
    if value["readonly_only"] is not True or any(value[key] is not False for key in ("network_mutations","device_writes","authorization_or_lock_held")):
        raise ValueError("Current triage mutation schema")
    if type(value["fatal_reason"]) is not str or value["fatal_reason"] not in FATAL_REASONS or type(value["observations"]) is not list or len(value["observations"])>2:
        raise ValueError("Current triage observations")
    for row in value["observations"]:
        _shape(row,("journal","pending","actors","owned"),())
        actor=row["actors"]
        _shape(actor,("complete","clear","reason","stage","errno","count_valid","counts","zombie_tasks_recorded","zombie_task_count","zombie_task_errno"),
            ("complete","clear","count_valid","zombie_tasks_recorded"))
        if (type(actor["reason"]) is not str or actor["reason"] not in ACTOR_REASONS or type(actor["stage"]) is not str or actor["stage"] not in ACTOR_STAGES or
                type(actor["counts"]) is not dict or set(actor["counts"])!=COUNT_KEYS or
                any(type(number) is not int or not 0<=number<=4095 for number in actor["counts"].values())):raise ValueError("Current triage actor")
        _errno(actor["errno"])
        _errno(actor["zombie_task_errno"])
        if actor["zombie_tasks_recorded"]:
            if (type(actor["zombie_task_count"]) is not int or not 1<=actor["zombie_task_count"]<=512 or
                    actor["reason"]!="empty_user_zombie" or actor["zombie_task_errno"]!=0):raise ValueError("Current triage zombie task semantics")
        elif actor["zombie_task_count"] is not None:raise ValueError("Current triage unknown task count")
        if actor["clear"] and (not actor["complete"] or actor["reason"]!="clear" or actor["stage"]!="done"):raise ValueError("Current triage clear semantics")
        if actor["complete"] and actor["reason"] not in ("clear","actor_present"):raise ValueError("Current triage actor complete")
        if actor["counts"]["examined"]>512 or actor["counts"]["examined"]>actor["counts"]["numeric_seen"]:raise ValueError("Current triage actor bounds")
        journal=row["journal"];jflags=("complete","same_boot","owned_recorded","process_absent")
        _shape(journal,jflags+("reason","errno","stage","ip_stage"),jflags);_errno(journal["errno"])
        if type(journal["stage"]) is not str or journal["stage"] not in JOURNAL_STAGES or type(journal["ip_stage"]) is not str or journal["ip_stage"] not in IP_STAGES:
            raise ValueError("Current triage journal stages")
        pending=row["pending"];pflags=("complete","present","safe","valid","lock_safe","exact_run","same_boot")
        _shape(pending,pflags+("reason","errno"),pflags);_errno(pending["errno"])
        for observed in (journal,pending):
            if type(observed["reason"]) is not str or observed["reason"] not in READ_REASONS or observed["complete"]!=(observed["reason"]=="complete"):
                raise ValueError("Current triage read semantics")
        if pending["complete"] and not all(pending[key] for key in ("safe","valid","lock_safe")):raise ValueError("Current triage pending semantics")
        owned=row["owned"];oflags=("complete","netlink_recorded","name_present","ifindex_present","wdev_present","phy_present",
            "exact_origin","collision","sysfs_recorded","sysfs_present","sysfs_identity_match","flags_recorded","flags_up")
        _shape(owned,oflags+("reason","errno","row_count","match_count","iftype"),oflags);_errno(owned["errno"])
        if type(owned["reason"]) is not str or owned["reason"] not in OWNED_REASONS or any(type(owned[key]) is not int or not 0<=owned[key]<=4095 for key in ("row_count","match_count")):
            raise ValueError("Current triage owned schema")
        if owned["match_count"]>owned["row_count"] or owned["iftype"] is not None and (type(owned["iftype"]) is not int or not 0<=owned["iftype"]<=12):
            raise ValueError("Current triage owned type")
        if owned["exact_origin"] and (owned["match_count"]!=1 or owned["collision"] or not all(owned[key+"_present"] for key in ("name","ifindex","wdev","phy"))):
            raise ValueError("Current triage origin semantics")
        if owned["flags_recorded"] and (not owned["sysfs_recorded"] or not owned["sysfs_present"]) or owned["flags_up"] and not owned["flags_recorded"]:
            raise ValueError("Current triage flags semantics")
        if owned["complete"] and (not owned["netlink_recorded"] or not owned["sysfs_recorded"] or owned["reason"] not in ("absent","exact","collision","type_changed","sysfs_absent")):
            raise ValueError("Current triage owned complete")
    if value["check_complete"] and (value["fatal_reason"]!="none" or not value["netlink_socket_closed"] or not value["snapshots_equal"] or
            len(value["observations"])!=2 or value["observations"][0]!=value["observations"][1] or
            not all(row[key]["complete"] for row in value["observations"] for key in ("journal","pending","actors","owned"))):
        raise ValueError("Current triage complete semantics")
    return value


def build_capsule():
    if hashlib.sha256(_data(Path(bounded.__file__),bounded.MAX_SOURCE_BYTES)).hexdigest()!=REFERENCE_SHA256:
        raise ValueError("Current triage fixed reference changed")
    capsule=bounded.build_capsule(True);safety=bounded.verify_reference()
    extra="RUN="+repr(RUN)+"\nTARGET="+repr(bounded.TARGET)+"\nMANIFEST_SHA256="+repr(bounded.MANIFEST_SHA256)+"\n"
    source=bounded.reference.probe_source(bounded.TARGET,safety,bounded.reader.old.READ_HELPERS+"\n"+BODY,extra)
    return capsule,bounded.bounded_program(source)


def _baseline_complete(value):
    return bool(type(value) is dict and all(value.get(key) is True for key in ("target_ok","stock_valid","query_ok","ipv4_complete")) and
        type(value.get("wifi")) is dict and type(value["wifi"].get("completed")) is bool and
        all(key in value for key in ("boot_id","stock","network_processes","interfaces","ipv4","ipv6_addresses_raw","ipv6_routes_raw","frequency","station_state_digest")) and
        type(value["boot_id"]) is str and bool(value["boot_id"]) and type(value["network_processes"]) is list and
        type(value["interfaces"]) is list and type(value["ipv4"]) is dict and type(value["frequency"]) is int and
        type(value["ipv6_addresses_raw"]) is bytes and type(value["ipv6_routes_raw"]) is bytes)


def run_check(_output=None):
    capsule,source=build_capsule();stamp=datetime.datetime.now().strftime("%Y%m%d-%H%M%S")+"-"+secrets.token_hex(4)
    out=Path(_output) if _output is not None else ROOT/"logs"/("MtaP011-V9CurrentTriage-"+stamp);out.mkdir(parents=True,exist_ok=False)
    report={"evidence_level":"P011_V9_CURRENT_TRIAGE_READONLY","pass":False,"check_complete":False,
        "candidate_identity":bounded.CANDIDATE,"checker_sha256":hashlib.sha256(_data(Path(__file__),bounded.MAX_SOURCE_BYTES)).hexdigest(),
        "bounded_reference_sha256":REFERENCE_SHA256,"readonly_only":True,"rf_trial_invoked":False,
        "network_mutations":False,"device_writes":False,"permissions_modified":False,"candidate_staging_requested":False,
        "journal_or_pending_writes":False,"recovery_invoked":False,"retry_invoked":False,"send_available":False,
        "authorization_or_lock_held":False,"historical_stop_failure_cause":"NOT_PROVEN","remote_statuses":{},
        "next_step":"REVIEW_CURRENT_EVIDENCE_NO_RESTORE_AUTHORIZATION"}
    adb=None;first=before=after=None;stage="target"
    call=lambda label,program:bounded.remote(adb,label,program,report["remote_statuses"])
    try:
        adb=Adb(out/"private-raw");stage="initial_files"
        first=bounded._files(call,"initial-fixed-v9-eight-readonly",capsule.initial_files["v9"],"v9")
        if not first["complete"]:raise ValueError("Current triage initial files")
        stage="before_baseline";before=call("before-current-triage-baseline",capsule.old_baseline)
        stage="observation";report["observation"]=validate_result(call("v9-current-triage-observation",source))
    except Exception:report["error_stage"]=stage;report["host_or_parse_error"]=True
    finally:
        if adb is not None:
            try:
                last=bounded._files(call,"last-fixed-v9-eight-readonly",capsule.last_files["v9"],"v9")
                report["current_eight_metadata_equal"]=bool(first and last["complete"] and last["identity_sha256"]==first["identity_sha256"])
            except Exception:report["last_files_failed"]=True
            try:after=call("after-current-triage-baseline",capsule.old_baseline)
            except Exception:report["after_check_failed"]=True
    report["before_baseline_read_complete"]=_baseline_complete(before);report["after_baseline_read_complete"]=_baseline_complete(after)
    known=report["before_baseline_read_complete"] and report["after_baseline_read_complete"]
    report["current_baseline_equal"]=bool(known and before==after)
    report["before_wifi_completed"]=bool(report["before_baseline_read_complete"] and before["wifi"]["completed"])
    report["after_wifi_completed"]=bool(report["after_baseline_read_complete"] and after["wifi"]["completed"])
    report["wifi_completed_preconditions"]=report["before_wifi_completed"] and report["after_wifi_completed"]
    for label,keys in (("same_boot",("boot_id",)),("stock_identity_equal",("stock",)),("original_process_identity_equal",("network_processes",)),
            ("full_interfaces_equal",("interfaces",)),("station_state_equal",("wifi","frequency","station_state_digest")),
            ("full_ipv4_equal",("ipv4",)),("full_ipv6_equal",("ipv6_addresses_raw","ipv6_routes_raw"))):
        report[label]=bool(known and all(key in before and key in after and before[key]==after[key] for key in keys))
    report["check_complete"]=bool(report.get("observation",{}).get("check_complete") is True and report["current_baseline_equal"] and
        report.get("current_eight_metadata_equal") is True and not any(report.get(key) for key in ("host_or_parse_error","after_check_failed","last_files_failed")))
    report["pass"]=report["check_complete"]
    (out/"result.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    (out/"README.txt").write_text("Fixed V9 current triage, observation only, not restoration or mutation authorization.\n"
        "Actor/journal/pending/owned observations independent; opaque/zombie/read errors do not prove absence.\n"
        "Current full before/after equality is separate from Wi-Fi completed prerequisites.\n"
        "Fixed staged eight files read-only before/after. No locks/staging/chmod/RF/address writes/stop/recovery/retry.\n"
        "Private records and argv are never public; raw baseline private. Historical stop cause NOT_PROVEN.\n",encoding="utf-8")
    return report,out


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--check-readonly",action="store_true",required=True);parser.parse_args()
    report,out=run_check();print(json.dumps(report,ensure_ascii=False,indent=2));print("RESULT_DIR="+str(out));return 0 if report["pass"] else 1


if __name__=="__main__":sys.exit(main())
