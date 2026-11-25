"""Receive preflight diagnostic only, explicit current P011 read-only evidence.
No State or receive admission is executed, and no RF/file publication occurs.
Keeps pending, locks, original stdout/stderr and remote/host exits untouched.
This standalone probe makes no reviewed/latest-State source assertion.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import zipfile

from device_probe import Adb, BASE, PINS

PROBE_PIN = (8759, 'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
MAX_PROC = 512
BOOL_FIELDS = frozenset(('complete', 'snapshots_consistent', 'stock_hashes_match',
    'stock_processes_match', 'stock_identities_unchanged', 'network_processes_unchanged',
    'basic_network_files_unchanged', 'interface_identities_unchanged', 'boot_unchanged',
    'p2p_pending_present', 'sta_journal_safe', 'ui_lock_present', 'native_lock_present',
    'temporary_menu_present', 'p2p_lock_safe'))
COUNT_FIELDS = frozenset(('sta_journal_entries', 'known_project_actors_first',
    'known_project_actors_second', 'prior_marker_actors_first', 'prior_marker_actors_second',
    'project_interfaces_first', 'project_interfaces_second'))
FIELDS = BOOL_FIELDS | COUNT_FIELDS

BODY = r'''
import hashlib,os,stat,time,sys
if os.geteuid()!=0 or os.uname()[4]!='armv7l' or tuple(sys.version_info[:3])!=(3,5,5):
 raise ValueError('target_identity')
A='/mnt/data/p011-toolbox';end=time.monotonic()+12
def read(path,limit):
 if time.monotonic()>=end:raise ValueError('invalid')
 with open(path,'rb') as handle:value=handle.read(limit+1)
 if len(value)>limit:raise ValueError('invalid')
 return value
def meta(value):return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_nlink,value.st_size,value.st_mtime,value.st_ctime)
def stock_hashes():
 result={}
 for path in PINS:
  before=os.lstat(path)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1 or not 0<before.st_size<=134217728:raise ValueError('invalid')
  h=hashlib.sha256();count=0
  with open(path,'rb') as handle:
   if meta(os.fstat(handle.fileno()))!=meta(before):raise ValueError('invalid')
   while True:
    if time.monotonic()>=end:raise ValueError('invalid')
    block=handle.read(65536)
    if not block:break
    count+=len(block)
    if count>134217728:raise ValueError('invalid')
    h.update(block)
   if count!=before.st_size or meta(os.fstat(handle.fileno()))!=meta(before):raise ValueError('invalid')
  if meta(os.lstat(path))!=meta(before):raise ValueError('invalid')
  result[path]=h.hexdigest()
 return result
def exists(path):
 try:os.lstat(path);return True
 except OSError as error:
  if error.errno==2:return False
  raise
def gates():
 journal=A+'/sessions/mta-network';safe=True;count=0;identities=[]
 for path in (A,A+'/sessions',journal):
  if not exists(path):break
  row=os.lstat(path);identities.append(meta(row))
  if not stat.S_ISDIR(row.st_mode) or os.path.realpath(path)!=path or row.st_uid!=os.geteuid():raise ValueError('invalid')
  if path==journal:
   if row.st_mode&0o777!=0o700:raise ValueError('invalid')
   names=os.listdir(path)
   if type(names) is not list or len(names)>16:raise ValueError('invalid')
   count=len(names)
 pending=exists('/tmp/p011-mta-p2p-device.pending')
 lock='/tmp/p011-mta-p2p-device.lock';locksafe=True
 if exists(lock):
  row=os.lstat(lock)
  locksafe=stat.S_ISREG(row.st_mode) and row.st_uid==os.geteuid() and row.st_nlink==1 and row.st_mode&0o077==0
 return (pending,safe,count,exists(A+'/mta-ui.lock'),exists(A+'/native.lock'),exists('/mnt/data/p011-menu'),locksafe,tuple(identities))
def identity(pid):
 raw=read('/proc/'+pid+'/stat',4096);at=raw.rindex(b')');fields=raw[at+2:].split()
 if len(fields)<20 or not fields[1].isdigit() or not fields[19].isdigit():raise ValueError('invalid')
 return (int(pid),int(fields[1]),int(fields[19]),raw[raw.index(b'(')+1:at],os.readlink('/proc/'+pid+'/exe'))
def processes():
 names=os.listdir('/proc')
 if type(names) is not list or len(names)>4096:raise ValueError('invalid')
 pids=sorted(name for name in names if type(name) is str and name.isdigit())
 if len(pids)>512:raise ValueError('invalid')
 project=[];prior=[];stock=[];network=[];races=0
 for pid in pids:
  if int(pid)==os.getpid():continue # Exclude only this current diagnostic process.
  try:
   raw=read('/proc/'+pid+'/cmdline',4096)
   if not raw:continue
   if raw[-1:]!=b'\0':raise ValueError('invalid')
   args=raw.split(b'\0')[:-1];row=identity(pid)
   known=(row[4].startswith(A+'/candidates/') or any((A+'/candidates/').encode('ascii') in item or (A+'/sessions/').encode('ascii') in item for item in args))
   marker=any(item in (b'mta-prior-readonly',b'mta-readonly-probe') for item in args)
   tracked=row[3] in (b'Z03',b'control_engine',b'weston',b'connmand',b'bluetoothd',b'wpa_supplicant')
   if known or marker or tracked:
    if read('/proc/'+pid+'/cmdline',4096)!=raw or identity(pid)!=row:raise ValueError('invalid')
    private=row+(hashlib.sha256(raw).hexdigest(),)
    if known:project.append(private)
    if marker:prior.append(private)
    if row[3] in (b'Z03',b'control_engine',b'weston'):stock.append(private)
    if tracked:network.append(private)
  except OSError as error:
   if error.errno in (2,3):
    races+=1
    if races>32:raise ValueError('invalid')
   else:raise
 return (tuple(project),tuple(prior),tuple(stock),tuple(network))
def interfaces():
 names=os.listdir('/sys/class/net')
 if type(names) is not list or len(names)>64:raise ValueError('invalid')
 rows=[];count=0
 for name in sorted(names):
  if type(name) is not str or not name or '/' in name or len(name)>15:raise ValueError('invalid')
  raw=read('/sys/class/net/'+name+'/ifindex',32).strip()
  if not raw.isdigit() or not 0<int(raw)<=2147483647:raise ValueError('invalid')
  rows.append((name,int(raw)))
  if name.startswith(('mta','p2p')):count+=1
 return (tuple(rows),count)
def snapshot():
 return (gates(),processes(),interfaces(),read('/proc/sys/kernel/random/boot_id',128),
  tuple(hashlib.sha256(read(path,1048576)).hexdigest() for path in ('/proc/net/route','/proc/net/if_inet6','/proc/net/ipv6_route')),stock_hashes())
def stock_ok(rows):
 return all(len([row for row in rows if row[3]==name])==1 for name in (b'Z03',b'control_engine',b'weston')) and all(row[4]=='/usr/bin/'+row[3].decode('ascii') for row in rows if row[3] in (b'Z03',b'control_engine'))
result={key:False for key in BOOL_FIELDS}
result.update({key:0 for key in COUNT_FIELDS})
try:
 first=snapshot();time.sleep(.05);second=snapshot();gate=second[0]
 result.update(complete=True,snapshots_consistent=first==second,stock_hashes_match=first[5]==PINS and second[5]==PINS,
  stock_processes_match=stock_ok(first[1][2]) and stock_ok(second[1][2]),stock_identities_unchanged=first[1][2]==second[1][2],
  network_processes_unchanged=first[1][3]==second[1][3],basic_network_files_unchanged=first[4]==second[4],
  interface_identities_unchanged=first[2][0]==second[2][0],boot_unchanged=first[3]==second[3],
  p2p_pending_present=first[0][0] or gate[0],sta_journal_safe=first[0][1] and gate[1],sta_journal_entries=max(first[0][2],gate[2]),
  ui_lock_present=first[0][3] or gate[3],native_lock_present=first[0][4] or gate[4],temporary_menu_present=first[0][5] or gate[5],
  p2p_lock_safe=first[0][6] and gate[6])
 for position,value in (('first',first),('second',second)):
  result['known_project_actors_'+position]=len(value[1][0]);result['prior_marker_actors_'+position]=len(value[1][1])
  result['project_interfaces_'+position]=value[2][1]
except Exception:pass
print('RESULT='+repr(result))
'''



def source():
    program = ('PINS=' + repr(PINS) + '\nBOOL_FIELDS=' + repr(tuple(sorted(BOOL_FIELDS))) +
               '\nCOUNT_FIELDS=' + repr(tuple(sorted(COUNT_FIELDS))) + '\n' + BODY)
    raw = program.encode('utf-8')
    if len(raw) > 12288 or any(len(line) > 2048 for line in raw.splitlines()):
        raise ValueError('diagnostic_source_budget')
    ast.parse(program, feature_version=(3, 5))
    return program


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-readonly', action='store_true', required=True)
    parser.parse_args()
    probe = BASE / 'host/device_probe.py'
    original_probe = probe.read_bytes()
    if (len(original_probe), hashlib.sha256(original_probe).hexdigest()) != PROBE_PIN:
        raise ValueError('transport_source_changed')
    program = source()
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
    out = BASE / 'results' / ('receive-prerequisite-readonly-' + stamp)
    out.mkdir()
    own_raw = Path(__file__).read_bytes()
    (out / 'private-source.py').write_bytes(own_raw)
    (out / 'private-target-source.py').write_bytes(program.encode('utf-8'))
    report = dict(schema='p011-receive-prerequisite-20261004',
        check_complete=False, observed_blockers_clear=False, device_invoked=False,
        state_receive_action_executed=False, native_receive_helper_executed=False,
        rf_requested=False, network_mutations=False, device_writes=False,
        pending_removed=False, recovery_invoked=False, reboot_invoked=False,
        receive_available=False, send_available=False, phone_tested=False,
        full_network_restore_verified=False, host_or_parse_error=False,
        source_sha256=hashlib.sha256(own_raw).hexdigest(),
        target_source_sha256=hashlib.sha256(program.encode('utf-8')).hexdigest(),
        transport_source_sha256=PROBE_PIN[1])
    try:
        adb = Adb(out / 'private-raw')
        report['device_invoked'] = True
        value = adb.python('receive-prerequisite-readonly', program, timeout=25)
        if (type(value) is not dict or set(value) != FIELDS or
            any(type(value[k]) is not bool for k in BOOL_FIELDS) or
            any(type(value[k]) is not int or not 0 <= value[k] <=
                (16 if k=='sta_journal_entries' else 64 if k.startswith('project_interfaces') else MAX_PROC)
                for k in COUNT_FIELDS)):
            raise ValueError('diagnostic_fixed_fields')
        report.update(value)
        report['check_complete'] = value['complete'] and value['snapshots_consistent']
        required = ('complete','snapshots_consistent','stock_hashes_match','stock_processes_match',
            'stock_identities_unchanged','network_processes_unchanged','basic_network_files_unchanged',
            'interface_identities_unchanged','boot_unchanged','sta_journal_safe','p2p_lock_safe')
        report['observed_blockers_clear'] = (all(value[k] for k in required) and
            not any(value[k] for k in ('p2p_pending_present','ui_lock_present',
                'native_lock_present','temporary_menu_present')) and
            all(value[k]==0 for k in COUNT_FIELDS))
    except Exception:
        report['host_or_parse_error'] = True
    report['sources_preserved'] = (probe.read_bytes()==original_probe and Path(__file__).read_bytes()==own_raw)
    raw = (json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True)+'\n').encode('ascii')
    readme = (b'Receive prerequisite read-only observation only. Never executes State receive, '
        b'helper/RF, staging, recovery, reboot or pending deletion. '
        b'check_complete refers only to two bounded consistent observations. '
        b'observed_blockers_clear is separate, not receive admission or complete restoration. '
        b'No credentials, user files, journal contents or physical output assessed. '
        b'Raw stdout/stderr and remote/host exits remain local private.\n')
    (out / 'result.json').write_bytes(raw)
    (out / 'README.txt').write_bytes(readme)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json',raw); bundle.writestr('README.txt',readme)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist()!=['result.json','README.txt'] or bundle.testzip() is not None or (
            bundle.read('result.json')!=raw or bundle.read('README.txt')!=readme):
            raise ValueError('diagnostic_zip_changed')
    print(json.dumps(dict(directory=str(out),result=report,
        zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()),sort_keys=True))
    return 0 if report['check_complete'] and report['sources_preserved'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

