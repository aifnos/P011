"""Fixed V9 owned-IP restore observation only; import/tests are HOST-only.

No locks, RF arming, journal/pending writes, controller, DELADDR or recovery.
PASS means complete current readonly evidence, not restoration/authorization.
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
STAGES = frozenset(("not_recorded", "journal", "pending", "backend", "actors", "identity", "sysfs", "ipv6", "snapshot", "delta", "final_journal", "done"))
REASONS = frozenset(("not_recorded", "complete", "deadline", "schema_or_read_error", "observations_changed", "descriptor_close"))
DIFFERENCES = ("boot", "original_processes", "station_identity", "original_interfaces", "frequency", "station_state", "original_ipv6")
BOOLS = frozenset(("same_boot", "stock_pins_match", "pending_exact", "process_absent", "actors_absent", "owned_origin_exact", "restore_type_allowed",
    "sysfs_identity_match", "flags_read_valid", "flags_up", "carrier_read_valid", "carrier_up", "carrier_read_unavailable_down", "ipv6_linklocal_only",
    "ipv6_restore_routes_allowed", "receipt_fsynced", "receipt_address_exact", "owned_address_unique", "routes_no_duplicates",
    "owned_routes_expected_subset", "current_ipv4_equals_baseline", "without_owned_equals_baseline",
    "actual_subset_removed_equals_baseline", "original_baseline_matches", "restore_preconditions_observed"))
COUNTS = frozenset(("owned_address_rows", "owned_route_rows", "expected_routes_present"))
IP_STAGES = frozenset(("confirmed", "delete_intent", "restored"))
DELTA_REASONS = frozenset(("accepted", "baseline_mismatch", "owned_delta_rejected"))


# The caller prepends fixed, already-reviewed READ_HELPERS. No lock functions
# or gate mutators are invoked. Original private records never enter RESULT.
BODY = r'''
import mta_send_wifi as wifi
import mta_ip_lease as lease_ip
stage='journal';end=time.monotonic()+25;backend=None;constructed=False;nl_socket=route_socket=None
value={'check_complete':False,'stage':'not_recorded','reason':'not_recorded',
 'first_second_equal':False,'netlink_sockets_closed':False,'observations':[],
 'restore_preconditions_observed':False,'authorization_or_lock_held':False,'network_mutations':False}
def at(label):
 global stage
 stage=label
 if time.monotonic()>=end:raise TimeoutError('readonly_deadline')
def actor_absence():
 at('actors');names=os.listdir('/proc')
 if sum(token.isdigit() for token in names)>512:raise ValueError('readonly_proc_limit')
 for token in names:
  at('actors')
  if not token.isdigit() or int(token)==os.getpid():continue
  try:blob=bounded('/proc/'+token+'/cmdline',65536)
  except OSError as error:
   if error.errno not in (2,3):raise
   if not process_absent({'pid':int(token)}):raise ValueError('readonly_actor_unknown')
   continue
  if type(blob) is not bytes or len(blob)>65536 or blob and blob[-1:]!=b'\0':raise ValueError('readonly_cmdline_truncated')
  if not blob:
   tail=bounded('/proc/'+token+'/stat',32768).rsplit(b')',1)
   if len(tail)!=2 or len(tail[1].split())<7:raise ValueError('readonly_empty_actor_unknown')
   flag=tail[1].split()[6]
   if not flag.isdigit() or not int(flag)&0x00200000:raise ValueError('readonly_empty_actor_unknown')
   continue
  args=blob.split(b'\0')
  if b'mta-prior-readonly' in args:return False
  if any(item.startswith((AREA+'/candidates/').encode('ascii')) and item.endswith(b'/runtime/mta_send_wifi.py') for item in args) and (b'--trial' in args or b'--recover' in args):return False
  if any(item.startswith((AREA+'/candidates/').encode('ascii')) and item.endswith(b'/native/mta-wpa-supplicant') for item in args):return False
 return True
def observe():
 at('journal');private_folder(RUN);record=private_record(RUN+'/p2p-lease.json');validate_journal3(record)
 wifi._journal_envelope(record)
 owned=record['owned'];resource=record['ip'];baseline=record['baseline']
 if owned is None or resource is None or resource['stage'] not in ('confirmed','delete_intent','restored') or record['process'] is None:
  raise ValueError('readonly_missing_confirmed_receipt')
 spec,address=lease_ip._validate_receipt(resource,owned)
 facts={'receipt_fsynced':resource['receipt_fsynced'] is True}
 at('pending');pending=pending_readonly()
 if not pending['safe'] or not pending['valid'] or not pending['lock_safe']:raise ValueError('readonly_pending_invalid')
 pending_record=private_record(DEVICE_PENDING) if pending['present'] else None
 facts['pending_exact']=bool(pending_record is not None and pending_record.get('journal')==RUN+'/p2p-lease.json' and
  pending_record.get('boot_id')==baseline['boot_id'] and identity3({key:pending_record[key] for key in IDENTITY3}))
 facts['same_boot']=baseline['boot_id']==backend.boot_id
 facts['stock_pins_match']=all(digest(path)==pin for path,pin in wifi.STOCK_PINS.items())
 facts['process_absent']=process_absent(record['process'])
 facts['actors_absent']=actor_absence()
 at('identity');rows=sorted(backend.nl.interfaces(),key=lambda row:row['wdev'])
 matched=[row for row in rows if row.get('name')==owned['name'] or row.get('wdev')==owned['wdev'] or row.get('ifindex')==owned['ifindex']]
 facts['owned_origin_exact']=bool(len(matched)==1 and wifi._origin_match(owned,matched[0]))
 facts['restore_type_allowed']=bool(facts['owned_origin_exact'] and matched[0]['iftype'] in (2,8,9))
 at('sysfs');root='/sys/class/net/'+owned['name']
 flags=bounded(root+'/flags',33).decode('ascii').strip()
 valid_flags=bool(re.match(r'^0x[0-9a-fA-F]{1,8}\Z',flags));up=bool(valid_flags and int(flags,16)&1)
 carrier=None
 try:carrier=bounded(root+'/carrier',4).decode('ascii').strip()
 except OSError as error:
  if error.errno!=22 or not valid_flags or up:raise
 index=bounded(root+'/ifindex',16).decode('ascii').strip()
 facts['flags_read_valid']=valid_flags;facts['flags_up']=up
 facts['carrier_read_valid']=carrier in ('0','1');facts['carrier_up']=carrier=='1'
 facts['carrier_read_unavailable_down']=carrier is None
 facts['sysfs_identity_match']=bool(re.match(r'^[0-9]{1,10}\Z',index) and int(index)==owned['ifindex'])
 at('ipv6');addresses=wifi._address_dump(owned['ifindex']);ipv6=[row for row in addresses if row['family']==6]
 facts['ipv6_linklocal_only']=wifi._only_link_local(ipv6)
 facts['ipv6_restore_routes_allowed']=wifi._owned_routes_safe(owned['name'],allow_ipv4=True)
 ipv6_routes=bounded('/proc/net/ipv6_route')
 at('snapshot');backend.ip_deadline=end
 actual=backend.snapshot(exclude_owned=owned)
 current=lease_ip.snapshot_from_data(actual['ipv4']);before=lease_ip.snapshot_from_data(baseline['ipv4'])
 differences=[]
 for label,keys in (('boot',('boot_id',)),('original_processes',('processes',)),('station_identity',('station',)),
  ('original_interfaces',('interfaces',)),('frequency',('frequency',)),('station_state',('station_state_digest',)),
  ('original_ipv6',('ipv6_route_digest','ipv6_address_digest'))):
  if any(actual.get(key)!=baseline.get(key) for key in keys):differences.append(label)
 facts['original_baseline_matches']=not differences
 at('delta');ours=[row for row in current.addresses if row.ifindex==owned['ifindex']]
 routes=[row for row in current.routes if row.oif==owned['ifindex']];expected=lease_ip._expected_routes(spec)
 counts={'owned_address_rows':len(ours),'owned_route_rows':len(routes),
  'expected_routes_present':sum(row in current.routes for row in expected)}
 if any(number>4095 for number in counts.values()):raise ValueError('readonly_count_limit')
 facts['receipt_address_exact']=address in ours;facts['owned_address_unique']=len(ours)==1 and ours[0]==address
 facts['routes_no_duplicates']=len(set(routes))==len(routes)
 facts['owned_routes_expected_subset']=bool(facts['routes_no_duplicates'] and all(row in expected for row in routes))
 facts['current_ipv4_equals_baseline']=lease_ip.snapshot_data(current)==lease_ip.snapshot_data(before)
 delta_reason='owned_delta_rejected';facts['without_owned_equals_baseline']=False
 try:
  cleaned=lease_ip.without_owned(current,resource,owned)
  facts['without_owned_equals_baseline']=lease_ip.snapshot_data(cleaned)==lease_ip.snapshot_data(before)
  delta_reason='accepted' if facts['without_owned_equals_baseline'] else 'baseline_mismatch'
 except lease_ip.IpLeaseError as error:
  if error.code!='ip_owned_delta_changed':raise
 facts['actual_subset_removed_equals_baseline']=False
 if facts['owned_address_unique'] and facts['owned_routes_expected_subset']:
  subset=ip.IpSnapshot(tuple(row for row in current.addresses if row!=address),
   tuple(row for row in current.routes if row not in routes),current.rules)
  facts['actual_subset_removed_equals_baseline']=lease_ip.snapshot_data(subset)==lease_ip.snapshot_data(before)
 # Only current observable old prerequisites, never guard/lock/write authority.
 required=('same_boot','stock_pins_match','pending_exact','process_absent','actors_absent','owned_origin_exact','restore_type_allowed',
  'sysfs_identity_match','ipv6_linklocal_only','ipv6_restore_routes_allowed','receipt_fsynced','original_baseline_matches')
 facts['restore_preconditions_observed']=bool(all(facts[key] is True for key in required) and
  (facts['current_ipv4_equals_baseline'] or facts['without_owned_equals_baseline']))
 at('final_journal')
 if private_record(RUN+'/p2p-lease.json')!=record:raise ValueError('readonly_journal_changed')
 public={'booleans':facts,'counts':counts,'baseline_differences':differences,'delta_reason':delta_reason,'ip_stage':resource['stage']}
 private={'journal':record,'pending':pending_record,'interfaces':rows,'flags':flags,'carrier':carrier,'sysfs_index':index,
  'addresses':addresses,'ipv6_routes':ipv6_routes,'snapshot':actual}
 return public,private
try:
 at('journal')
 if digest(TARGET+'/SOURCE.sha256')!=MANIFEST_SHA256:raise ValueError('readonly_manifest')
 backend=wifi.LinuxBackend.__new__(wifi.LinuxBackend)
 at('backend');wifi.LinuxBackend.__init__(backend,BINARY,TARGET+'/native/mta-wifi-caps',RUN,allow_rf=False)
 nl_socket=backend.nl.sock;route_socket=backend.ip_transport.socket
 if any(type(item.fileno()) is not int or item.fileno()<0 for item in (nl_socket,route_socket)):raise ValueError('readonly_socket_identity')
 constructed=True
 first,first_private=observe();value['observations'].append(first)
 second,second_private=observe();value['observations'].append(second)
 value['first_second_equal']=first==second and first_private==second_private
 value['reason']='complete' if value['first_second_equal'] else 'observations_changed';stage='done'
except TimeoutError:value['reason']='deadline'
except BaseException:value['reason']='schema_or_read_error'
finally:
 closed=constructed
 if backend is not None:
  for name in ('monitor','command','diagnostics','ip_transport','nl','guard'):
   owned_resource=getattr(backend,name,None)
   if owned_resource is not None:
    try:owned_resource.close()
    except BaseException:closed=False
 try:
  closed=bool(closed and nl_socket is not None and route_socket is not None and
   type(nl_socket.fileno()) is int and nl_socket.fileno()==-1 and
   type(route_socket.fileno()) is int and route_socket.fileno()==-1 and backend.ip_transport.closed is True)
 except BaseException:closed=False
 value['netlink_sockets_closed']=closed
 if not closed:value['reason']='descriptor_close'
 value['stage']=stage
 value['check_complete']=bool(value['reason']=='complete' and len(value['observations'])==2 and closed)
 value['restore_preconditions_observed']=bool(value['check_complete'] and value['observations'][0]['booleans']['restore_preconditions_observed'])
print('RESULT='+repr(value))
'''


def validate_result(value):
    fields = {"check_complete","stage","reason","first_second_equal","netlink_sockets_closed","observations",
              "restore_preconditions_observed","authorization_or_lock_held","network_mutations"}
    if (type(value) is not dict or set(value)!=fields or type(value["stage"]) is not str or value["stage"] not in STAGES or
            type(value["reason"]) is not str or value["reason"] not in REASONS or type(value["observations"]) is not list or len(value["observations"])>2 or
            any(type(value[key]) is not bool for key in fields-{"stage","reason","observations"}) or
            value["authorization_or_lock_held"] is not False or value["network_mutations"] is not False):raise ValueError("Restore readonly schema")
    for row in value["observations"]:
        if (type(row) is not dict or set(row)!={"booleans","counts","baseline_differences","delta_reason","ip_stage"} or
                type(row["booleans"]) is not dict or set(row["booleans"])!=BOOLS or any(type(flag) is not bool for flag in row["booleans"].values()) or
                type(row["counts"]) is not dict or set(row["counts"])!=COUNTS or any(type(number) is not int or not 0<=number<=4095 for number in row["counts"].values()) or
                row["counts"]["expected_routes_present"]>4 or type(row["baseline_differences"]) is not list or
                any(type(name) is not str or name not in DIFFERENCES for name in row["baseline_differences"]) or
                row["baseline_differences"]!=[name for name in DIFFERENCES if name in row["baseline_differences"]] or
                type(row["delta_reason"]) is not str or row["delta_reason"] not in DELTA_REASONS or
                type(row["ip_stage"]) is not str or row["ip_stage"] not in IP_STAGES):raise ValueError("Restore readonly observation schema")
        facts=row["booleans"]
        if facts["original_baseline_matches"]!=(not row["baseline_differences"]):raise ValueError("Restore baseline semantics")
        if (facts["without_owned_equals_baseline"] is True)!=(row["delta_reason"]=="accepted"):raise ValueError("Restore delta semantics")
        if facts["owned_address_unique"] and (row["counts"]["owned_address_rows"]!=1 or not facts["receipt_address_exact"]):raise ValueError("Restore address semantics")
        if facts["carrier_read_unavailable_down"] and (not facts["flags_read_valid"] or facts["flags_up"] or facts["carrier_read_valid"] or facts["carrier_up"]):
            raise ValueError("Restore unavailable carrier semantics")
        required=("same_boot","stock_pins_match","pending_exact","process_absent","actors_absent","owned_origin_exact","restore_type_allowed",
                  "sysfs_identity_match","ipv6_linklocal_only","ipv6_restore_routes_allowed","receipt_fsynced","original_baseline_matches")
        expected=all(facts[key] is True for key in required) and (facts["current_ipv4_equals_baseline"] or facts["without_owned_equals_baseline"])
        if facts["restore_preconditions_observed"]!=expected:raise ValueError("Restore prerequisites semantics")
    if value["check_complete"] and (value["reason"]!="complete" or value["stage"]!="done" or len(value["observations"])!=2 or
            value["observations"][0]!=value["observations"][1] or not value["first_second_equal"] or not value["netlink_sockets_closed"]):raise ValueError("Restore complete semantics")
    if value["restore_preconditions_observed"] and (not value["check_complete"] or not all(row["booleans"]["restore_preconditions_observed"] for row in value["observations"])):
        raise ValueError("Restore observed prerequisites semantics")
    return value


def build_capsule():
    if hashlib.sha256(_data(Path(bounded.__file__),bounded.MAX_SOURCE_BYTES)).hexdigest()!=REFERENCE_SHA256:
        raise ValueError("Restore fixed bounded entry changed")
    capsule=bounded.build_capsule(True)
    safety=bounded.verify_reference()
    extra="RUN="+repr(RUN)+"\nTARGET="+repr(bounded.TARGET)+"\nMANIFEST_SHA256="+repr(bounded.MANIFEST_SHA256)+"\n"
    source=bounded.reference.probe_source(bounded.TARGET,safety,bounded.reader.old.READ_HELPERS+"\n"+BODY,extra)
    return capsule,bounded.bounded_program(source)


def run_check(_output=None):
    capsule,source=build_capsule()
    stamp=datetime.datetime.now().strftime("%Y%m%d-%H%M%S")+"-"+secrets.token_hex(4)
    out=Path(_output) if _output is not None else ROOT/"logs"/("MtaP011-V9RestoreReadOnly-"+stamp)
    out.mkdir(parents=True,exist_ok=False)
    report={"evidence_level":"P011_V9_CURRENT_RESTORE_READONLY_OBSERVATION","pass":False,"check_complete":False,
        "candidate_identity":bounded.CANDIDATE,"checker_sha256":hashlib.sha256(_data(Path(__file__),bounded.MAX_SOURCE_BYTES)).hexdigest(),
        "bounded_reference_sha256":REFERENCE_SHA256,"readonly_only":True,"rf_trial_invoked":False,
        "network_mutations":False,"candidate_staging_requested":False,"permissions_modified":False,
        "journal_or_pending_writes":False,"recovery_invoked":False,"retry_invoked":False,"send_available":False,
        "authorization_or_lock_held":False,"restore_preconditions_observed":False,"historical_stop_failure_cause":"NOT_PROVEN",
        "remote_statuses":{},"next_step":"REVIEW_CURRENT_EVIDENCE_NO_RESTORE_AUTHORIZATION"}
    adb=None;before=after=None;stage="target";groups=("fixed16","v7","v8","v9");first={}
    call=lambda label,program:bounded.remote(adb,label,program,report["remote_statuses"])
    try:
        adb=Adb(out/"private-raw")
        for group in groups:
            stage="initial_"+group
            item=bounded._files(call,bounded._label("initial",group),capsule.initial_files[group],group)
            if not item["complete"]:raise ValueError("Restore initial files")
            first[group]=item
        stage="before_baseline";before=call("before-restore-readonly-baseline",capsule.old_baseline)
        stage="observation";report["observation"]=validate_result(call("v9-owned-restore-readonly-observation",source))
        for group in groups:
            stage="last_"+group
            item=bounded._files(call,bounded._label("last",group),capsule.last_files[group],group)
            report[group+"_metadata_unchanged"]=item["complete"] and item["identity_sha256"]==first[group]["identity_sha256"]
            if not report[group+"_metadata_unchanged"]:raise ValueError("Restore last files")
    except Exception:report["error_stage"]=stage;report["host_or_parse_error"]=True
    finally:
        if adb is not None:
            try:after=call("after-restore-readonly-baseline",capsule.old_baseline)
            except Exception:report["after_check_failed"]=True
    observation=report.get("observation",{})
    report["full_current_baseline_unchanged"]=bool(type(before) is dict and type(after) is dict and before.get("query_ok") is True and after.get("query_ok") is True and
        before.get("stock_valid") is True and after.get("stock_valid") is True and before.get("wifi",{}).get("completed") is True and before==after)
    report["check_complete"]=bool(observation.get("check_complete") is True and report["full_current_baseline_unchanged"] and
        all(report.get(group+"_metadata_unchanged") is True for group in groups) and not report.get("host_or_parse_error") and not report.get("after_check_failed"))
    report["pass"]=report["check_complete"]
    report["restore_preconditions_observed"]=bool(report["check_complete"] and observation.get("restore_preconditions_observed") is True)
    (out/"result.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    (out/"README.txt").write_text("Fixed current V9 ownedrun readonly restore observation, not restoration or mutation authorization.\n"
        "Exact staged old16/V7/V8/V9 pins+metadata before/after, two same-origin observations and complete unchanged current baseline.\n"
        "Strict old full-route receipt gate remains separately false when expected routes missing; exact actual subset facts are observations only.\n"
        "No locks/allow_rf/controller/journal/pending/IP writes/DELADDR/remove/retry. Current facts do not prove the historical stop failure cause.\n"
        "Raw private, public fixed bool/count/enum only; no ZIP, phone/send not tested.\n",encoding="utf-8")
    return report,out


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-readonly",action="store_true",required=True)
    parser.parse_args()
    report,out=run_check();print(json.dumps(report,ensure_ascii=False,indent=2));print("RESULT_DIR="+str(out))
    return 0 if report["pass"] else 1


if __name__=="__main__":sys.exit(main())
