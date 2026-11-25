"""Fixed V5/V6 file permissions and pins, with independent read-only baseline.

No staging, chmod/chown, recovery or trial entry exists. Import is HOST-only;
ROOT must review the source before explicitly invoking --check-readonly.
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
import device_prior_journal_readonly as previous
import device_p2p_v6diag as reference


PREVIOUS_CHECKER_SHA256 = "3e8192c9396b50e5432e21bf1754ef7bc6e3104d45af215d6591a0a120c7e617"
COMMON_SIZES = {"SOURCE.sha256":654,"native/mta-wifi-caps":21460,"native/mta-wpa-supplicant":1351192,
                "runtime/mta_ip.py":22049,"runtime/mta_ip_lease.py":18704,"runtime/mta_safety.py":4720,"runtime/p011_json.py":8061}
V5_MANIFEST = "0f2a45489fd3e03b0b56b9bb083cf2d978f005d8260e9148339616d7856591b8"
V6_MANIFEST = "916a02d44aeeaf0dcb24a3eaa57b7762fad5f503e3dabac83bed34df10780daf"
COMMON_PINS = {"native/mta-wifi-caps":"9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6",
    "native/mta-wpa-supplicant":"e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301",
    "runtime/mta_ip.py":"1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5",
    "runtime/mta_ip_lease.py":"39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c",
    "runtime/mta_safety.py":"03f77794db1fa8bebf44f56a479d5feaa6aef0e0f490ad4e577ad5bb6b190a81",
    "runtime/p011_json.py":"fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88"}
CANDIDATES = {
    "v5":{"identity":V5_MANIFEST[:16],"manifest":V5_MANIFEST,
          "pins":dict(COMMON_PINS,**{"SOURCE.sha256":V5_MANIFEST,"runtime/mta_send_wifi.py":"96f808a9ef7cbaf011bb3254a23c01cbda6d7e09e016ad948c5dba89b671bd87"}),
          "sizes":dict(COMMON_SIZES,**{"runtime/mta_send_wifi.py":67474})},
    "v6":{"identity":V6_MANIFEST[:16],"manifest":V6_MANIFEST,
          "pins":dict(COMMON_PINS,**{"SOURCE.sha256":V6_MANIFEST,"runtime/mta_send_wifi.py":"82bb5ba72c887608543d64018e2979cd27d6ee112036de9a701f0e5709de4faa"}),
          "sizes":dict(COMMON_SIZES,**{"runtime/mta_send_wifi.py":78359})},
}
RELATIVES = frozenset(CANDIDATES["v5"]["pins"])
ROW_BOOL_FIELDS = frozenset(("owner_matches_euid","file_regular","no_symlink","not_other_writable","full_sha_match","size_match"))
ROW_FIELDS = ROW_BOOL_FIELDS | {"candidate","relative","mode"}
STAGES = frozenset(("not_recorded","directory_safety","file_lstat","file_open","file_read","file_identity",
                    "file_pin","candidate_contents","deadline","complete"))
REASONS = frozenset(("not_recorded","file_not_regular","file_identity_changed","file_pin_mismatch",
    "candidate_contents_invalid","readonly_permission_deadline","unmapped_value_error","os_error","unexpected_exception"))
CLASSES = frozenset(("none","value_error","os_error","unexpected_exception"))
RESULT_BOOL_FIELDS = frozenset(("diagnostic_complete","pins_verified","permissions_gate_satisfied"))
RESULT_FIELDS = RESULT_BOOL_FIELDS | {"files","file_count","outer_stage","outer_candidate","outer_relative","reason","error_class","errno"}


BODY = r'''
end=time.monotonic()+25
stage='directory_safety';alias='not_recorded';relative='not_recorded'
result={'diagnostic_complete':False,'pins_verified':False,'permissions_gate_satisfied':False,'files':[],
 'file_count':0,'outer_stage':'not_recorded','outer_candidate':'not_recorded','outer_relative':'not_recorded',
 'reason':'not_recorded','error_class':'none','errno':0}
def deadline():
 if time.monotonic()>=end:raise ValueError('readonly_permission_deadline')
def file_identity(value):
 return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
def read_file(path,size,pin):
 global stage
 stage='file_lstat';deadline();before=os.lstat(path)
 row={'candidate':alias,'relative':relative,'mode':before.st_mode&0o777,
  'owner_matches_euid':before.st_uid==os.geteuid(),'file_regular':stat.S_ISREG(before.st_mode),
  'no_symlink':not stat.S_ISLNK(before.st_mode),'not_other_writable':before.st_mode&0o022==0,
  'full_sha_match':False,'size_match':before.st_size==size}
 result['files'].append(row)
 if not row['file_regular'] or not row['no_symlink']:raise ValueError('file_not_regular')
 stage='file_open';deadline();fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  os.set_inheritable(fd,False)
  if file_identity(os.fstat(fd))!=file_identity(before):raise ValueError('file_identity_changed')
  stage='file_read';hashvalue=hashlib.sha256();count=0
  while count<size:
   deadline();blob=os.read(fd,min(65536,size-count))
   if not blob:break
   count+=len(blob);hashvalue.update(blob)
  deadline();extra=os.read(fd,1)
  row['size_match']=row['size_match'] and count==size and not extra
  row['full_sha_match']=row['size_match'] and hashvalue.hexdigest()==pin
  stage='file_identity';deadline()
  if file_identity(os.fstat(fd))!=file_identity(before) or file_identity(os.lstat(path))!=file_identity(before):
   raise ValueError('file_identity_changed')
 finally:os.close(fd)
 stage='file_pin'
 if not row['size_match'] or not row['full_sha_match']:raise ValueError('file_pin_mismatch')
try:
 for alias in ('v5','v6'):
  relative='not_recorded';known=CANDIDATES[alias];base=AREA+'/candidates/mta-01-'+known['identity']
  stage='directory_safety';deadline()
  private_folder(base);private_folder(base+'/runtime');private_folder(base+'/native')
  for relative in sorted(known['pins']):read_file(base+'/'+relative,known['sizes'][relative],known['pins'][relative])
  # Bounded descriptor verification above proves exact manifest and all seven
  # pinned payload bytes. Preserve canonical/private/no-link/exact-file-set
  # safety without reopening writable manifests through an unbounded reader.
  relative='not_recorded';stage='candidate_contents';deadline();observed=set()
  for folder,dirs,files in os.walk(base,followlinks=False):
   deadline();owned_directory(folder)
   if len(dirs)+len(files)>32 or any(os.path.islink(folder+'/'+name) for name in dirs):raise ValueError('candidate_contents_invalid')
   observed.update(os.path.relpath(folder+'/'+name,base).replace(os.sep,'/') for name in files)
   if len(observed)>8:raise ValueError('candidate_contents_invalid')
  if observed!=set(known['pins']):raise ValueError('candidate_contents_invalid')
 stage='complete';result['diagnostic_complete']=True;result['pins_verified']=True
 result['permissions_gate_satisfied']=all(row['owner_matches_euid'] and row['file_regular'] and row['no_symlink'] and row['not_other_writable'] for row in result['files'])
except Exception as error:
 result['outer_stage']=stage;result['outer_candidate']=alias;result['outer_relative']=relative
 if isinstance(error,OSError):
  result['error_class']='os_error';result['reason']='os_error';number=error.errno
  result['errno']=number if type(number) is int and 1<=number<=4095 else 0
 elif isinstance(error,ValueError):
  result['error_class']='value_error';token=error.args[0] if len(error.args)==1 and type(error.args[0]) is str else None
  result['reason']=token if token in ('file_not_regular','file_identity_changed','file_pin_mismatch','candidate_contents_invalid','readonly_permission_deadline') else 'unmapped_value_error'
 else:result['error_class']='unexpected_exception';result['reason']='unexpected_exception'
result['file_count']=len(result['files'])
print('RESULT='+repr(result))
'''


def validate_result(value):
    if type(value) is not dict or set(value) != RESULT_FIELDS or any(type(value[key]) is not bool for key in RESULT_BOOL_FIELDS):
        raise ValueError("Permissions readonly result schema")
    if (type(value["files"]) is not list or type(value["file_count"]) is not int or value["file_count"] != len(value["files"]) or not 0 <= value["file_count"] <= 16 or
            type(value["outer_stage"]) is not str or value["outer_stage"] not in STAGES or value["outer_candidate"] not in ("not_recorded","v5","v6") or
            type(value["outer_relative"]) is not str or value["outer_relative"] not in RELATIVES | {"not_recorded"} or
            type(value["reason"]) is not str or value["reason"] not in REASONS or type(value["error_class"]) is not str or value["error_class"] not in CLASSES or
            type(value["errno"]) is not int or not 0 <= value["errno"] <= 4095):
        raise ValueError("Permissions readonly fixed fields")
    expected=[(alias,relative) for alias in ("v5","v6") for relative in sorted(RELATIVES)]
    for index,row in enumerate(value["files"]):
        if (type(row) is not dict or set(row) != ROW_FIELDS or any(type(row[key]) is not bool for key in ROW_BOOL_FIELDS) or
                type(row["candidate"]) is not str or type(row["relative"]) is not str or (row["candidate"],row["relative"]) != expected[index] or
                type(row["mode"]) is not int or not 0 <= row["mode"] <= 0o777 or row["not_other_writable"] != (row["mode"] & 0o022 == 0)):
            raise ValueError("Permissions readonly row schema")
    if value["diagnostic_complete"]:
        if (len(value["files"]) != 16 or not value["pins_verified"] or value["error_class"] != "none" or value["reason"] != "not_recorded" or value["errno"] != 0 or
                not all(row["full_sha_match"] and row["size_match"] and row["file_regular"] and row["no_symlink"] for row in value["files"]) or
                value["permissions_gate_satisfied"] != all(row["owner_matches_euid"] and row["not_other_writable"] for row in value["files"])):
            raise ValueError("Permissions readonly completion schema")
    elif value["pins_verified"] or value["permissions_gate_satisfied"]:
        raise ValueError("Permissions readonly incomplete cannot grant gates")
    return value


def verify_reference():
    if hashlib.sha256(_data(Path(previous.__file__),previous.MAX_SOURCE_BYTES)).hexdigest() != PREVIOUS_CHECKER_SHA256:
        raise ValueError("Original readonly checker changed")
    safety=previous.verify_reference()
    old=ROOT / "logs/MtaP011-P2pV5Freeze-20261001-044135-4c11e2d6/private-candidate"
    for alias,folder in (("v5",old),("v6",previous.FROZEN)):
        known=CANDIDATES[alias]
        for relative,pin in known["pins"].items():
            raw=_data(folder / relative,2*1024*1024)
            if len(raw) != known["sizes"][relative] or hashlib.sha256(raw).hexdigest() != pin:
                raise ValueError("Fixed permission source reference changed")
    return safety


def source(safety):
    body=reference.READ_HELPERS + "\nCANDIDATES=" + repr(CANDIDATES) + "\n" + BODY
    body="if digest(" + repr(previous.TARGET + "/SOURCE.sha256") + ")!=" + repr(V6_MANIFEST) + ":raise ValueError('readonly_manifest_pin')\n" + body
    value=reference.probe_source(previous.TARGET,safety,body)
    ast.parse(value,feature_version=(3,5))
    if len(value.encode("utf-8")) > previous.MAX_SOURCE_BYTES:raise ValueError("Readonly source bound")
    return value


def run_check(output=None):
    safety=verify_reference();baseline=previous.source(safety);program=source(safety)
    stamp=datetime.datetime.now().strftime("%Y%m%d-%H%M%S")+"-"+secrets.token_hex(4)
    out=Path(output) if output else ROOT / "logs" / ("MtaP011-CandidatePermissionsReadOnly-"+stamp)
    out.mkdir(parents=True,exist_ok=False)
    report={"evidence_level":"P011_FIXED_CANDIDATE_PERMISSIONS_READONLY","pass":False,"check_complete":False,
        "checker_sha256":hashlib.sha256(_data(Path(__file__),previous.MAX_SOURCE_BYTES)).hexdigest(),
        "radio_operations":False,"network_configuration":False,"device_writes":False,"candidate_staged":False,
        "permissions_modified":False,"recovery_invoked":False,"retry_invoked":False,"send_available":False,
        "ip_installation":"NOT_TESTED","phone_interop":"NOT_TESTED","remote_statuses":{},
        "next_step":"REVIEW_EXACT_PERMISSION_FACTS_NO_AUTO_REPAIR_OR_TRIAL"}
    adb=None;before=after=diagnostic=None;stage="target"
    try:
        adb=Adb(out / "private-raw");stage="before"
        before=previous.remote(adb,"before-permissions-readonly",baseline,report["remote_statuses"])
        if not reference.preflight_ok(before):raise ValueError("Readonly preflight")
        stage="permission_files"
        diagnostic=validate_result(previous.remote(adb,"fixed-permission-files-readonly",program,report["remote_statuses"]))
        report["diagnostic"]=diagnostic
    except Exception:report["host_or_parse_error"]=True;report["error_stage"]=stage
    finally:
        if adb is not None:
            try:after=previous.remote(adb,"after-permissions-readonly",baseline,report["remote_statuses"])
            except Exception:report["after_check_failed"]=True
        gates={};reference.add_independent_gates(gates,before,after,None)
        fields=("stock_independent_unchanged","wifi_state_fingerprint_unchanged","station_state_digest_unchanged","frequency_unchanged","route_digest_unchanged",
            "full_ipv4_addresses_unchanged","full_ipv4_routes_unchanged","full_ipv4_rules_unchanged","full_ipv4_readback_unchanged","full_ipv6_readback_unchanged",
            "ipv6_address_digest_unchanged","ipv6_route_digest_unchanged","same_boot","network_processes_unchanged","interface_identities_unchanged","wifi_completed_after",
            "no_p2p_interfaces_after","no_project_mta_interfaces_after","no_private_wpa_processes_after","no_project_trial_actors_after","global_pending_clear_independent")
        report.update({field:gates[field] for field in fields})
        report["check_complete"]=bool(diagnostic and diagnostic["diagnostic_complete"] and diagnostic["pins_verified"] and
            all(report[field] is True for field in fields) and not report.get("host_or_parse_error") and not report.get("after_check_failed"))
        report["pass"]=report["check_complete"]
    (out / "result.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    (out / "README.txt").write_text("Read-only permission/size/full-pin facts for fixed V5 and V6 aliases, manifest + seven payloads each.\n"
        "O_RDONLY|O_NOFOLLOW, fstat, bounded exact bytes and final metadata identity comparison; canonical/private/no-symlink/exact file sets.\n"
        "PASS/check_complete means complete unchanged-state evidence, NOT acceptable permissions, repaired admission, GO/IP or phone transfer.\n"
        "No chmod/chown, staging, new trial/recovery/retry. Public ZIP contains result/README only; raw/host exits remain private.\n",encoding="utf-8")
    archive=Path(str(out)+".sanitized.zip")
    with zipfile.ZipFile(archive,"x",zipfile.ZIP_DEFLATED) as bundle:
        for name in ("result.json","README.txt"):bundle.write(out / name,name)
    return report,out,archive


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-readonly",action="store_true",required=True)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args();report,out,archive=run_check(args.output)
    print(json.dumps(report,ensure_ascii=False,indent=2));print("RESULT_DIR="+str(out));print("RESULT_ZIP="+str(archive))
    return 0 if report["check_complete"] else 1


if __name__ == "__main__":sys.exit(main())
