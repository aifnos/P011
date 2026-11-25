"""Latest-State smoke prerequisite observation, NOT a State/UI smoke runner.

Import and --validate-host are HOST-only. --check-readonly sends exactly one
fixed short read-only payload. There is no staging, candidate execution, UI,
State instantiation, socket creation, RF, restore, cleanup or ZIP API here.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import sys
import zlib

from device_probe import Adb, BASE, ROOT, PINS


MAX_SOURCE_BYTES = 12288
MAX_SOURCE_LINE_BYTES = 2048
MAX_COMMAND_BYTES = 3500
MAX_PROC = 512
REVIEWED_PINS = {
    'runtime/mta_service.py': '6b52785c10db47ad5a8da7b8fdafe0ac4e08c27e7fabe1c3a69b35ebb44fdadd',
    'runtime/mta_wifi.py': '62322b09fe4fd96bf6d49d8a2f7ac416e9a9d4dadcb3df23a6330e3205bcd017',
    'runtime/mta_toolbox_session.py': 'de4a872d7dce18ae19d8478d73173e573de72f5ecd8890c098b18fd3fb0cddfa',
    'runtime/mta_ui_session.py': '146b974c86d1affc0da6db3ab2f1d81a8d95ef6e54f0466cb8a07d4c5f3e404f',
    'tests/test_service_session_lifecycle.py': '90a2785f67c91d08273e0467f27fca9776dd66d41fa1cba035f6fd98d62933e7',
    'tests/test_service_integration.py': '55c9e5556a32b68b3e94e89aaf7ffec0bc3bd01f79010fd0771dd7007af41e57',
    'tests/test_wifi.py': '6777ea1982b8d4ca3cc66ec808c936393a75ac921200eddf4e5d6527e8b6ddd3',
    'docs/STATE_SESSION_INTEGRATION_REVIEW.md': '24bca1ab822b339778871e23a763a3516df1e4a2155aa7f47f4242fb4edccc4d',
}
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
import hashlib,os,stat,time
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


def compressed_command(program):
    payload = base64.b64encode(zlib.compress(program.encode('utf-8'))).decode('ascii')
    return ('python3 -B -c "import base64,zlib;exec(zlib.decompress(base64.b64decode(\'' +
            payload + '\')));print(\'MTA_REMOTE_OK\')"; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')


def source():
    program = ('PINS=' + repr(PINS) + '\nBOOL_FIELDS=' + repr(tuple(sorted(BOOL_FIELDS))) +
               '\nCOUNT_FIELDS=' + repr(tuple(sorted(COUNT_FIELDS))) + '\n' + BODY)
    encoded = program.encode('utf-8')
    if len(encoded) > MAX_SOURCE_BYTES or any(len(line) > MAX_SOURCE_LINE_BYTES for line in encoded.splitlines()):
        raise ValueError('Readonly source budget')
    ast.parse(program, feature_version=(3, 5))
    if len(compressed_command(program).encode('ascii')) >= MAX_COMMAND_BYTES:
        raise ValueError('Readonly short argv budget')
    return program


def verify_reviewed_sources(base=BASE):
    """Only the named eight reviewed HOST files; never copy/chmod a candidate."""
    base = Path(base)
    for name, expected in REVIEWED_PINS.items():
        path = base / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Reviewed source differs')
    return True


def validate_result(value):
    if type(value) is not dict or set(value) != FIELDS:
        raise ValueError('Readonly fixed fields')
    if any(type(value[name]) is not bool for name in BOOL_FIELDS):
        raise ValueError('Readonly boolean fields')
    if any(type(value[name]) is not int or not 0 <= value[name] <= (16 if name == 'sta_journal_entries' else 64 if name.startswith('project_interfaces') else MAX_PROC)
           for name in COUNT_FIELDS):
        raise ValueError('Readonly bounded counts')
    if value['snapshots_consistent'] and (not value['complete'] or any(value[key + '_first'] != value[key + '_second']
            for key in ('known_project_actors', 'prior_marker_actors', 'project_interfaces'))):
        raise ValueError('Readonly consistency')
    return value


def blockers_clear(value):
    validate_result(value)
    required = ('complete', 'snapshots_consistent', 'stock_hashes_match', 'stock_processes_match',
        'stock_identities_unchanged', 'network_processes_unchanged', 'basic_network_files_unchanged',
        'interface_identities_unchanged', 'boot_unchanged', 'sta_journal_safe', 'p2p_lock_safe')
    return (all(value[name] is True for name in required) and not any(value[name] for name in
        ('p2p_pending_present', 'ui_lock_present', 'native_lock_present', 'temporary_menu_present')) and
        all(value[name] == 0 for name in COUNT_FIELDS))


def run_check(output=None):
    """Future explicit ROOT-only dispatch: just observe; there is no next phase."""
    program = source()
    verify_reviewed_sources()
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
    out = Path(output) if output else ROOT / 'logs' / ('MtaP011-StateSmokeReadOnly-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    report = {'evidence_level': 'P011_STATE_SMOKE_PREREQUISITE_READONLY', 'pass': False,
        'check_complete': False, 'observed_blockers_clear': False, 'staging_allowed': False,
        'run_allowed': False, 'latest_state_run': 'NOT_IMPLEMENTED', 'ui_pages': 'NOT_IMPLEMENTED',
        'saved_worker_closed': 'NOT_IMPLEMENTED', 'transport_closed': 'NOT_IMPLEMENTED',
        'full_ipv4_baseline': 'NOT_ASSESSED', 'prior_receipts': 'NOT_ASSESSED',
        'all_resources_absent': 'NOT_PROVEN', 'radio_operations': False, 'device_writes': False,
        'cleanup_invoked': False, 'signals_sent': False, 'candidate_executed': False,
        'reviewed_source_pins_match': True, 'host_or_parse_error': False,
        'checker_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'target_source_sha256': hashlib.sha256(program.encode('utf-8')).hexdigest(),
        'next_step': 'SEPARATE_ROOT_REVIEW_REQUIRED'}
    try:
        adb = Adb(out / 'private-raw')
        value = validate_result(adb.python('state-smoke-prerequisite-readonly', program, timeout=25))
        report.update(value)
        report['check_complete'] = value['complete'] and value['snapshots_consistent']
        report['pass'] = report['check_complete']
        report['observed_blockers_clear'] = blockers_clear(value)
    except Exception:
        report['host_or_parse_error'] = True
    (out / 'result.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    (out / 'README.txt').write_text('Prerequisite observation only, NOT latest State/UI smoke or staging admission.\n'
        'All target operations are bounded fixed filesystem/proc reads; no State, socket, thread or subprocess is created by the payload.\n'
        'PASS means two complete consistent snapshots. Pending and known blockers are separately reported.\n'
        'staging_allowed and run_allowed are always false; no staging/run function exists.\n'
        'Basic proc network fingerprints are not a full IPv4/all-tables/rules or Wi-Fi COMPLETED readback.\n'
        'No journal contents, credentials, user files or images are read. Raw transport output stays private.\n'
        'No ZIP is created. Old failures and actual UI/TLS evidence retain their original scope.\n', encoding='utf-8')
    return report, out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--validate-host', action='store_true')
    mode.add_argument('--check-readonly', action='store_true')
    args = parser.parse_args(argv)
    if args.validate_host:
        program = source()
        verify_reviewed_sources()
        print(json.dumps({'evidence_level': 'HOST_PAYLOAD_VALIDATION', 'reviewed_source_pins_match': True,
            'source_bytes': len(program.encode('utf-8')), 'command_bytes': len(compressed_command(program).encode('ascii')),
            'device_invoked': False, 'latest_state_run': 'NOT_IMPLEMENTED', 'staging_allowed': False,
            'run_allowed': False}, sort_keys=True))
        return 0
    report, out = run_check()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print('RESULT_DIR=' + str(out))
    return 0 if report['check_complete'] else 1


if __name__ == '__main__':
    sys.exit(main())
