"""User-authorized, conditional administrative retirement of one fixed GO64.

Default SOURCE mode creates only a new private PC backup/result. Explicit
--retire-single rechecks original records, actors and actual network DATA under
the same existing device/journal OFDs, then moves the original pending inode
into its original run with RENAME_NOREPLACE. No record is deleted or rewritten.
No CLIENT history, RF, old runner, process signal, restore/admission grant.

ARM Linux 4.14 ABI: renameat2=382; RENAME_NOREPLACE=1. Primary definitions:
https://raw.githubusercontent.com/torvalds/linux/v4.14/arch/arm/tools/syscall.tbl
https://raw.githubusercontent.com/torvalds/linux/v4.14/include/uapi/linux/fs.h
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]
SOURCE_PINS = (
    ('host/device_go_pending_readonly_20261004.py',26460,'97ab846cc8e9fa822d145cc5fb73dadddb4ccda8ebfe94c894c0fa7a15cc89c3'),
    ('host/device_go_retirement_network_readonly_v3.py',42620,'7e0dce26b6f143f6be5ca44d7d6722fb60160d94b13201bddce18252725c2169'),
)
ARCHIVE_NAME = 'go-pending.archived-20261004-v1'


def sha(raw): return hashlib.sha256(raw).hexdigest()


def require(value,code):
    if value is not True: raise ValueError(code)


def fixed_module(path,size,pin):
    raw=(BASE/path).read_bytes()
    require(len(raw)==size and sha(raw)==pin,'source_pin')
    module=types.ModuleType('fixed_retirement_'+Path(path).stem)
    module.__file__=str(BASE/path)
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module,raw


EXTRA = r'''
import signal

def admin_activity_alarm(signum,frame):raise ValueError('administrative_activity_deadline')
def admin_cleanup_alarm(signum,frame):raise ValueError('administrative_cleanup_deadline')
if signal.getsignal(signal.SIGALRM)!=signal.SIG_DFL or signal.getitimer(signal.ITIMER_REAL)!=(0.0,0.0):fail('outer_alarm_unknown')
signal.signal(signal.SIGALRM,admin_activity_alarm)
signal.setitimer(signal.ITIMER_REAL,max(0.000001,end-time.monotonic()))
administrative=dict(network_observed=False,network_configuration_verified=False,
 stock_restart_only=False,ipv6_counter_difference_only=False,negative_final_verified=False,
 original_host_backup_verified=HOST_BACKUP_VERIFIED,rename_called=False,rename_outcome_known=False,rename_return=None,
 rename_errno=None,original_inode_archived=False,source_pending_absent=False,
 original_journal_unchanged=False,directories_fsynced=False,network=None)
result['administrative']=administrative
_NETWORK_PRIVATE=None

def retired_network():
 global _NETWORK_PRIVATE
 raw=base64.b64decode(NETWORK_SOURCE_B64.encode('ascii'),validate=True)
 if (len(raw),hashlib.sha256(raw).hexdigest())!=NETWORK_PROGRAM_PIN:fail('network_program_pin')
 namespace={'__name__':'fixed_go64_admin_network_private'}
 _NETWORK_PRIVATE=namespace
 exec(compile(raw,'<fixed-go64-admin-network>','exec'),namespace)
 value=namespace['observe_current'](end)
 administrative['network_observed']=True
 if (type(value)is not dict or value['complete']is not True or value['stage']!='complete' or
  value['reason']!='ok' or value['current_baseline_stable']is not True or
  value['old_record_unchanged']is not True or value['resource_inventory_closed']is not True or
  value['close_errors'] or len(value['passes'])!=2):fail('network_observation_incomplete')
 for group in ('fd_rows','socket_rows','child_rows','pipe_rows'):
  if not value[group] or any(r['closed']is not True or r['unknown']is not False for r in value[group]):fail('network_inventory_unknown')
 comparison=value['historical_data_comparison'];historical=namespace['cfg']['historical']
 if set(comparison)!=set(namespace['BASELINE_FIELDS']) or any(type(v)is not bool for v in comparison.values()):fail('network_comparison_shape')
 if any(comparison[k]is not True for k in comparison if k not in ('stock_actors','ipv6_routes')):fail('network_configuration_changed')
 for observation in value['passes']:
  current=observation['data'];interfaces=current['interfaces']
  if (not interfaces or any(r['ifindex']is None or r['iftype'] in (8,9,10) or
   r['name'].startswith('p2p') or re.fullmatch('mta[0-9a-f]{8}',r['name']) for r in interfaces)):fail('p2p_present_or_unknown')
  oldactors={a['exe'].rsplit('/',1)[-1]:a for a in historical['stock_actors']}
  newactors={a['exe'].rsplit('/',1)[-1]:a for a in current['stock_actors']}
  if len(oldactors)!=6 or len(newactors)!=6 or set(oldactors)!=set(newactors):fail('stock_actor_inventory')
  for role,original in oldactors.items():
   actual=newactors[role]
   if role=='Z03':
    if original['exe']!=actual['exe'] or original['argv_sha']!=actual['argv_sha']:fail('stock_z03_changed')
   elif namespace['actor_key'](original)!=namespace['actor_key'](actual):fail('stock_daemon_changed')
  # Metric, flags, destinations, gateways and interface stay exact. Only the
  # kernel's two use/ref counters are not configuration; raw rows are retained.
  oldrows=sorted(tuple(r[:6]+r[8:]) for r in historical['ipv6_routes'])
  newrows=sorted(tuple(r[:6]+r[8:]) for r in current['ipv6_routes'])
  if oldrows!=newrows:fail('ipv6_configuration_changed')
 administrative['network_configuration_verified']=True
 administrative['stock_restart_only']=comparison['stock_actors']is False
 administrative['ipv6_counter_difference_only']=comparison['ipv6_routes']is False
 # This is DATA projection only. Retain the real namespace/inventory; omit
 # only the unused native structural-key repr from the printable data copy.
 printable=dict(value);printable['passes']=[{k:v for k,v in r.items() if k!='ipv4_structural'} for r in value['passes']]
 administrative['network']=printable
 now();lock_current()

def retire_one():
 if (HOST_BACKUP_VERIFIED is not True or ARCHIVE_NAME!='go-pending.archived-20261004-v1' or
  sys.byteorder!='little' or ctypes.sizeof(ctypes.c_void_p)!=4 or os.uname()[2]!='4.14.174'):fail('archive_platform_or_backup')
 if (result['record_match']is not True or result['records_unchanged']is not True or
  result['same_boot']is not True or result['old_period_expired']is not True or
  result['actors_paths_absent']is not True or result['project_netdevs_absent']is not True or
  result['old_unix_live_absent']is not True or any(r['old_endpoint_paths'] for r in result['network_passes'])):fail('initial_conditions')
 retired_network()
 if records()!=result['before']:fail('final_record_changed')
 finalactors=actor_pass();finalnet=network_pass()
 result['actor_passes'].append(finalactors);result['network_passes'].append(finalnet)
 if (not all(a['all_paths_absent'] for a in finalactors) or finalnet['project_netdevs'] or
  finalnet['old_unix_live'] or finalnet['old_endpoint_paths']):fail('final_negative_condition')
 boot,unused=read_file('/proc/sys/kernel/random/boot_id',128,'final_archive_boot')
 if boot.strip().decode('ascii')!=cfg['boot']:fail('final_boot_changed')
 administrative['negative_final_verified']=True;lock_current();now()
 source_dir=anchors[3][0];destination_dir=anchors[-1][0]
 if source_dir['path']!=root or destination_dir['path']!=run:fail('archive_parent_identity')
 if source_dir['metadata'][0]!=destination_dir['metadata'][0]:fail('archive_cross_device')
 archive_path=run+'/'+ARCHIVE_NAME
 if path_state(archive_path)is not None:fail('archive_destination_exists')
 held=opened(pending_path,'original_pending_for_move');m=held['metadata']
 if m!=result['before']['pending_metadata'] or m[3:7]!=(0,0,1,340) or stat.S_IMODE(m[2])!=0o600:fail('final_marker_identity')
 if os.read(held['fd'],341)!=expected_pending or os.read(held['fd'],1)!=b'':fail('final_marker_bytes')
 if meta(os.fstat(held['fd']))!=m or meta(os.stat('p011-mta-p2p-device.pending',dir_fd=source_dir['fd'],follow_symlinks=False))!=m:fail('final_marker_identity')
 lock_current();now()
 syscall=libc.syscall;syscall.restype=ctypes.c_long
 syscall.argtypes=(ctypes.c_long,ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
 administrative['rename_called']=True;result['read_only']=False;ctypes.set_errno(0)
 answer=syscall(382,source_dir['fd'],b'p011-mta-p2p-device.pending',destination_dir['fd'],ARCHIVE_NAME.encode('ascii'),1)
 administrative['rename_return']=answer;administrative['rename_errno']=ctypes.get_errno()
 if answer!=0:fail('archive_syscall_failed')
 # No fallback overwrite, link/unlink, marker deletion or old-journal update.
 observed=meta(os.fstat(held['fd']));named=meta(os.stat(ARCHIVE_NAME,dir_fd=destination_dir['fd'],follow_symlinks=False))
 if observed[:8]!=m[:8] or named!=observed:fail('archive_inode_changed')
 if path_state(pending_path)is not None:fail('archive_source_still_present')
 if os.lseek(held['fd'],0,os.SEEK_SET)!=0 or os.read(held['fd'],341)!=expected_pending or os.read(held['fd'],1)!=b'':fail('archive_bytes_changed')
 archived,am=read_file(archive_path,131072,'archive_readback',True)
 if archived!=expected_pending or am!=observed:fail('archive_readback_changed')
 administrative['original_inode_archived']=True;administrative['source_pending_absent']=True
 os.fsync(source_dir['fd']);os.fsync(destination_dir['fd']);administrative['directories_fsynced']=True
 journal,jm=read_file(journal_path,131072,'original_journal_after_move',True)
 if journal!=expected_journal or jm!=result['before']['journal_metadata']:fail('original_journal_changed')
 administrative['original_journal_unchanged']=True;lock_current();now()
 administrative['rename_outcome_known']=True
'''


def make_source(old,old_inputs,old_config,network,network_inputs,network_config):
    network_program=network.make_source(network_inputs,network_config).encode('ascii')
    body=old.BODY
    start="\ntry:\n stage='anchors'"
    hook=" lock_current();now();stage='complete'\n"
    require(body.count(start)==body.count(hook)==1,'original_hook_count')
    body=body.replace(start,'\n'+EXTRA+start).replace(hook," stage='conditional_archive';retire_one()\n"+hook)
    cleanup="finally:\n # Locks stay held"
    complete="result['complete']=first_error is None"
    require(body.count(cleanup)==body.count(complete)==1,'original_cleanup_hook_count')
    body=body.replace(cleanup,"finally:\n signal.setitimer(signal.ITIMER_REAL,0.0)\n signal.signal(signal.SIGALRM,admin_cleanup_alarm)\n signal.setitimer(signal.ITIMER_REAL,30.0)\n # Locks stay held")
    body=body.replace(complete,"signal.setitimer(signal.ITIMER_REAL,0.0)\nsignal.signal(signal.SIGALRM,signal.SIG_DFL)\n"+complete)
    original=old.source(old_inputs,old_config)
    require(original.endswith(old.BODY),'original_program_suffix')
    preamble=original[:-len(old.BODY)]
    program=(preamble+old.b64_literal('NETWORK_SOURCE_B64',network_program)+
             'NETWORK_PROGRAM_PIN='+repr((len(network_program),sha(network_program)))+'\n'+
             'ARCHIVE_NAME='+repr(ARCHIVE_NAME)+'\nHOST_BACKUP_VERIFIED=True\n'+body)
    require(len(program.encode('ascii'))<262144 and max(map(len,program.splitlines()))<=2048,'target_budget')
    ast.parse(program,feature_version=(3,5))
    return program


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--retire-single',action='store_true')
    args=parser.parse_args()
    modules=[fixed_module(*pin) for pin in SOURCE_PINS]
    old,network=modules[0][0],modules[1][0]
    old_inputs=old.fixed_inputs();network_inputs=network.fixed_inputs()
    old_config=old.fixed_config(old_inputs);network_config=network.configuration(network_inputs)
    require(old_config['run_token']==network_config['run_token'] and old_config['boot']==network_config['boot'] and
            old_config['pending_b64']==network_config['pending_b64'] and old_config['journal_b64']==network_config['journal_b64'],
            'fixed_config_identity')
    out=BASE/'results'/('go64-single-retirement-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    private=out/'private-raw';private.mkdir(parents=True,exist_ok=False)
    backups={name:base64.b64decode(old_config[key],validate=True) for name,key in
             (('original-pending.bin','pending_b64'),('original-journal.bin','journal_b64'))}
    for name,raw in backups.items():
        with (private/name).open('xb') as handle:
            handle.write(raw);handle.flush();os.fsync(handle.fileno())
        require((private/name).read_bytes()==raw,'host_backup_readback')
    own=Path(__file__).read_bytes()
    (private/'host-source.py').write_bytes(own)
    for (path,size,pin),(module,raw) in zip(SOURCE_PINS,modules):
        (private/Path(path).name).write_bytes(raw)
    program=make_source(old,old_inputs,old_config,network,network_inputs,network_config)
    (private/'target-source.py').write_bytes(program.encode('ascii'))
    value=None;error=None;transport_unchanged=False
    if args.retire_single:
        try:
            transport_input=network_inputs[BASE/'host/device_probe.py']
            transport=types.ModuleType('fixed_go64_retirement_transport');transport.__file__=str(BASE/'host/device_probe.py')
            exec(compile(transport_input,transport.__file__,'exec'),transport.__dict__)
            adb_before=transport.ADB.read_bytes();adb=transport.Adb(private)
            # Waiting covers the existing 30 s activity plus the independent
            # network/outer 30 s close budgets; it grants no extra activity.
            value=adb.python('go64-retire-single',program,timeout=95)
            transport_unchanged=transport.ADB.read_bytes()==adb_before
            (private/'remote-result.json').write_text(json.dumps(value,indent=2,sort_keys=True,
                default=lambda v:{'bytes_b64':base64.b64encode(v).decode('ascii')} if type(v)is bytes else None)+'\n',encoding='ascii')
        except BaseException as failure:
            error=type(failure).__name__; (private/'host-error.txt').write_text(error+'\n',encoding='ascii')
    unchanged=(Path(__file__).read_bytes()==own and old.fixed_inputs()==old_inputs and network.fixed_inputs()==network_inputs and
               all((BASE/path).read_bytes()==raw for (path,size,pin),(module,raw) in zip(SOURCE_PINS,modules)))
    admin=value.get('administrative',{}) if type(value)is dict else {}
    require(type(admin)is dict,'administrative_result_shape')
    report=dict(schema='p011-go64-single-administrative-retirement-v1',mode='device' if args.retire_single else 'source',
        source_preserved=unchanged,source_ast_verified=True,host_backup_verified=True,host_backup_file_count=2,
        host_backup_bytes=sum(map(len,backups.values())),target_source_bytes=len(program.encode('ascii')),
        target_source_sha256=sha(program.encode('ascii')),device_invoked=args.retire_single,host_error=error,
        transport_unchanged=transport_unchanged,
        target_complete=type(value)is dict and value.get('complete')is True,
        actual_local_fds_closed=type(value)is dict and value.get('local_fds_closed')is True,
        network_configuration_verified=admin.get('network_configuration_verified')is True,
        stock_z03_restart_only=admin.get('stock_restart_only')is True,
        ipv6_counter_difference_only=admin.get('ipv6_counter_difference_only')is True,
        final_old_actor_endpoint_negative=admin.get('negative_final_verified')is True,
        archive_syscall_called=admin.get('rename_called')is True,
        archive_outcome_verified=admin.get('rename_outcome_known')is True,
        archive_mutation_outcome_unknown=args.retire_single and (
            type(value)is not dict or type(admin.get('rename_called'))is not bool or
            type(admin.get('rename_outcome_known'))is not bool or
            admin.get('rename_called')is True and admin.get('rename_outcome_known')is not True),
        original_marker_inode_archived=admin.get('original_inode_archived')is True,
        source_pending_absent=admin.get('source_pending_absent')is True,
        original_journal_unchanged=admin.get('original_journal_unchanged')is True,
        archive_directories_fsynced=admin.get('directories_fsynced')is True,
        target_record_deleted=False,target_record_bytes_rewritten=False,client_history_touched=False,
        radio_mutations=False,candidate_started=False,process_signalled=False,
        original_native_inventory_closure_verified=False,original_snapshot_key_verified=False,
        old_restored_receipt_issued=False,full_network_restore_verified=False,
        admission_issued=False,receive_available=False,send_available=False,phone_tested=False,private_raw_included=False)
    report['passed']=(unchanged and error is None and (not args.retire_single or
        transport_unchanged and all(report[k] for k in ('target_complete','actual_local_fds_closed',
        'network_configuration_verified','final_old_actor_endpoint_negative','original_marker_inode_archived',
        'source_pending_absent','original_journal_unchanged','archive_directories_fsynced','archive_outcome_verified'))))
    raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode('ascii')
    readme=(b'One fixed old GO64 administrative record retirement, NOT an old restore/Native closure or new receive grant.\n'
        b'Default SOURCE only. Two byte-exact PC originals are saved/read back before explicit target action.\n'
        b'Target rechecks fixed records, original actor/endpoint absence and actual full read-only network DATA under the same existing OFD locks. Current configured network must match original; only Z03 PID/start restart with unchanged exe/argv and IPv6 use/ref counters may differ.\n'
        b'Sole record change is ARM Linux renameat2 RENAME_NOREPLACE moving the original pending inode to its original run; no overwrite/fallback/unlink, journal update, CLIENT history or RF action. Raw originals and identifiers stay private.\n')
    (out/'result.json').write_bytes(raw);(out/'README.txt').write_bytes(readme)
    with zipfile.ZipFile(out/'public-result.zip','x',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json',raw);archive.writestr('README.txt',readme)
    print(json.dumps(dict(directory=str(out),result=report),sort_keys=True))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
