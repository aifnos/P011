"""Explicit bounded current-PTY/prior-readonly-actor observation; no cleanup.

Import and HOST tests never construct ADB. Only --check-readonly dispatches one
fixed short inline Python program. Raw transport output remains private.
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
import zipfile
import zlib

from device_probe import Adb, ROOT


MAX_SOURCE_BYTES=8192
MAX_SOURCE_LINE_BYTES=2048
MAX_COMMAND_BYTES=3500
MAX_PROC=512
COUNTS=tuple(prefix+'_'+position for position in ('first','second') for prefix in
             ('exact_readonly_actors','other_read_count_actors','other_prior_marker_actors'))
FIELDS=frozenset(COUNTS+('stdin_is_tty','tty_mode_observed','icanon','echo',
                        'snapshot_first_complete','snapshot_second_complete','snapshots_consistent'))
SOURCE=r'''
import os,time
try:import termios
except ImportError:termios=None
result={'stdin_is_tty':None,'tty_mode_observed':None if termios is None else False,'icanon':None,'echo':None}
try:
 value=os.isatty(0)
 result['stdin_is_tty']=value if type(value) is bool else None
 if termios is not None and result['stdin_is_tty'] is True:
  value=termios.tcgetattr(0)
  if type(value) not in (list,tuple) or len(value)!=7 or type(value[3]) is not int:raise ValueError('tty_shape')
  result.update(tty_mode_observed=True,icanon=bool(value[3]&termios.ICANON),echo=bool(value[3]&termios.ECHO))
except Exception:pass
marker=b'mta-prior-readonly';head=b'import sys;exec(sys.stdin.buffer.read(';tail=b'))'
fixed=[b'python3',b'-B',b'-c',head+b'32270'+tail,marker]
def read(path,limit):
 with open(path,'rb') as stream:return stream.read(limit+1)
def start(pid):
 raw=read('/proc/'+pid+'/stat',4096)
 if len(raw)>4096:raise ValueError('stat_bound')
 value=raw[raw.rindex(b')')+2:].split()[19]
 if not value.isdigit() or not 0<int(value)<10**20:raise ValueError('stat_shape')
 return int(value)
def snapshot():
 counts=[0,0,0];identities=set();complete=True;races=0;end=time.monotonic()+2
 try:names=os.listdir('/proc')
 except Exception:return counts,identities,False
 if type(names) is not list or len(names)>4096:return counts,identities,False
 pids=sorted(name for name in names if type(name) is str and name.isdigit())
 if len(pids)>512:return counts,identities,False
 for pid in pids:
  if time.monotonic()>=end:return counts,identities,False
  try:
   raw=read('/proc/'+pid+'/cmdline',4096)
   if len(raw)>4096:complete=False;continue
   if not raw:continue
   if not raw.endswith(b'\0'):complete=False;continue
   args=raw.split(b'\0')[:-1]
   if marker not in args:continue
   kind=2
   if args==fixed:kind=0
   elif len(args)==5 and args[:3]==fixed[:3] and args[4]==marker:
    code=args[3]
    if code.startswith(head) and code.endswith(tail):
     number=code[len(head):-len(tail)]
     if 1<=len(number)<=6 and number.isdigit() and number==str(int(number)).encode('ascii') and int(number)!=32270:kind=1
   counts[kind]+=1
   first=start(pid)
   if read('/proc/'+pid+'/cmdline',4096)!=raw or start(pid)!=first:complete=False;continue
   identities.add((int(pid),first,tuple(args),kind))
  except OSError as error:
   if error.errno in (2,3):
    races+=1
    if races>32:return counts,identities,False
   else:complete=False
  except Exception:complete=False
 return counts,identities,complete
first=snapshot();time.sleep(.05);second=snapshot()
for position,value in (('first',first),('second',second)):
 for index,key in enumerate(('exact_readonly_actors','other_read_count_actors','other_prior_marker_actors')):
  result[key+'_'+position]=value[0][index]
 result['snapshot_'+position+'_complete']=value[2]
result['snapshots_consistent']=first[2] and second[2] and first[0]==second[0] and first[1]==second[1]
print('RESULT='+repr(result))
'''


def compressed_command(program):
    """Exactly mirrors Adb.python's short branch; never admit its stdin branch."""
    payload=base64.b64encode(zlib.compress(program.encode('utf-8'))).decode('ascii')
    return ('python3 -B -c "import base64,zlib;exec(zlib.decompress(base64.b64decode(\''+
            payload+'\')));print(\'MTA_REMOTE_OK\')"; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')


def source():
    encoded=SOURCE.encode('utf-8')
    if len(encoded)>MAX_SOURCE_BYTES or any(len(line)>MAX_SOURCE_LINE_BYTES for line in encoded.splitlines()):
        raise ValueError('Readonly source budget')
    ast.parse(SOURCE,feature_version=(3,5))
    if len(compressed_command(SOURCE).encode('ascii'))>=MAX_COMMAND_BYTES:
        raise ValueError('Readonly short argv budget')
    return SOURCE


def validate_result(value):
    if type(value) is not dict or set(value)!=FIELDS:raise ValueError('Readonly fixed fields')
    for name in ('stdin_is_tty','tty_mode_observed','icanon','echo'):
        if value[name] is not None and type(value[name]) is not bool:raise ValueError('Readonly tty types')
    for name in ('snapshot_first_complete','snapshot_second_complete','snapshots_consistent'):
        if type(value[name]) is not bool:raise ValueError('Readonly snapshot types')
    if any(type(value[name]) is not int or not 0<=value[name]<=MAX_PROC for name in COUNTS):
        raise ValueError('Readonly bounded counts')
    if any(sum(value[key+'_'+position] for key in ('exact_readonly_actors','other_read_count_actors','other_prior_marker_actors'))>MAX_PROC
           for position in ('first','second')):raise ValueError('Readonly total counts')
    observed=value['tty_mode_observed'] is True
    if observed:
        if value['stdin_is_tty'] is not True or any(type(value[name]) is not bool for name in ('icanon','echo')):
            raise ValueError('Readonly observed tty consistency')
    elif value['icanon'] is not None or value['echo'] is not None:raise ValueError('Readonly unknown tty consistency')
    if value['snapshots_consistent']:
        if not value['snapshot_first_complete'] or not value['snapshot_second_complete'] or any(
            value[key+'_first']!=value[key+'_second'] for key in ('exact_readonly_actors','other_read_count_actors','other_prior_marker_actors')):
            raise ValueError('Readonly snapshot consistency')
    return value


def run_check(output=None):
    program=source()
    stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4)
    out=Path(output) if output else ROOT/'logs'/('MtaP011-TtyActorReadOnly-'+stamp)
    out.mkdir(parents=True,exist_ok=False)
    report={'evidence_level':'P011_CURRENT_TTY_EXACT_READONLY_ACTOR_OBSERVATION','pass':False,'check_complete':False,
            'checker_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'target_source_sha256':hashlib.sha256(program.encode('utf-8')).hexdigest(),
            'radio_operations':False,'device_writes':False,'signals_sent':False,'cleanup_invoked':False,
            'historical_timeout_unchanged':True,'historical_tty_mode':'NOT_PROVEN',
            'all_resources_absent':'NOT_PROVEN','next_step':'REVIEW_CURRENT_OBSERVATION_NO_AUTOMATIC_ACTION'}
    try:
        adb=Adb(out/'private-raw')
        value=validate_result(adb.python('current-tty-exact-prior-actor-readonly',program,timeout=15))
        report.update(value)
        report['check_complete']=value['snapshot_first_complete'] and value['snapshot_second_complete'] and value['snapshots_consistent']
        # PASS is collection completion, not RF readiness or universal absence.
        report['pass']=report['check_complete']
        report['observed_prior_marker_actors_zero']=report['check_complete'] and all(value[key]==0 for key in COUNTS)
    except Exception:report['host_or_parse_error']=True;report['observed_prior_marker_actors_zero']=False
    (out/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'README.txt').write_text('One current PTY termios/TTY observation and two bounded exact prior-readonly actor snapshots only.\n'
        'No stty change, signal, kill, cleanup, RF, network, candidate execution, user data or remote subprocess.\n'
        'PASS means completed consistent observation, NOT RF admission or absence of every resource.\n'
        'All three prior-marker actor classes must be zero and both snapshots complete before any later separately reviewed admission.\n'
        'Missing termios: tty_mode_observed=None; ioctl/not-TTY observation unavailable: False; icanon/echo remain None.\n'
        'Current PTY mode cannot establish the timed-out prior command actual termios state. Private raw remains local.\n',encoding='utf-8')
    archive=Path(str(out)+'.sanitized.zip')
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as bundle:
        for name in ('result.json','README.txt'):bundle.write(out/name,name)
    return report,out,archive


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-readonly',action='store_true',required=True)
    parser.parse_args()
    report,out,archive=run_check()
    print(json.dumps(report,ensure_ascii=False,indent=2));print('RESULT_DIR='+str(out));print('RESULT_ZIP='+str(archive))
    sys.exit(0 if report['check_complete'] else 1)
