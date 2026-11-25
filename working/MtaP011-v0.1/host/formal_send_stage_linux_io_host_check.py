"""Fixed new Linux-root HOST file IO method; no old test or target invocation."""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
TEST = 'tests/test_formal_send_stage_linux_io.py'
SELF = 'host/formal_send_stage_linux_io_host_check.py'
CMD = 'HOST_MTA_FORMAL_SEND_STAGE_LINUX_IO_CHECK.cmd'
STAGE = 'candidate/formal-send-stage-v1/runtime/formal_send_stage.py'
CATALOGS = (
    ('candidate/formal-send-v1/assets/ordinary-source-manifest.json',
     18219, '0aff3d932addb257962cb1aa89857784ddaaec945d34ee75c43e95fab15d2fb1'),
    ('candidate/formal-send-v1/assets/asset-sources.json',
     23552, '27366f2510d07f2dd74eb65533c314f48d7b437bb574744c57203e28746a076a'),
    ('candidate/formal-send-v1/assets/sender-source-manifest.json',
     3677, 'be67d8cec589b4e54235d8205660a67f02a188f23e99251bf2219b35b147f3d5'),
)
PINS = {
    TEST:(27380, '97a31af2bc9002c5f6b04da05c034f19764b478816a88620fe1856e4555ff495'),
    STAGE:(37382, 'cdb73ecb883ee72a3cb8e45726987b3da2fc7d92fe1cb8c73a0b2de82f743806'),
}
TOTALS = (('sender', 27, 2402458), ('observer', 41, 1440449), ('ordinary', 37, 1266713))
CASES = (
    'real_linux_root_flags_without_arm_platform_claim',
    'actual_constructor_context_clock_and_original_profile',
    'sender27_actual_write_readback_and_complete_readonly_recheck',
    'observer41_actual_write_readback_and_complete_readonly_recheck',
    'ordinary37_actual_write_readback_and_complete_readonly_recheck',
    'absent_inventory_inspect_does_not_create',
    'partial_inventory_refused_without_overwrite_or_clear',
    'exclusive_existing_file_refused_bytes_unchanged',
    'nofollow_file_symlink_refused_target_unchanged',
    'nofollow_directory_symlink_refused',
    'changed_directory_edge_refused_original_fd_retained',
    'created_child_metadata_changes_do_not_replace_held_identity',
    'fault_tail_file_metadata_change_is_refused',
    'fault_final_inventory_new_child_is_refused',
    'fault_fstat_unknown_fd_not_closed_by_stager',
    'fault_duplicate_open_fd_marks_both_unknown_without_close',
    'expired_original_deadline_still_closes_known_fds_and_proves_ebadf',
    'changed_row_fd_never_closes_foreign_or_original_descriptor',
    'actual_enoent_no_fd_receipt_and_close_are_bounded',
    'fixed_input_bytes_preserved_and_no_runtime_admission',
)
ACTUAL_FIELDS = ('actual_frozen_definitions_loaded', 'actual_fixed_stage_constructor',
    'actual_context_now_clock_thread', 'actual_linux_root_permissions',
    'actual_normal_openat_excl_nofollow_cloexec', 'actual_normal_directory_fd_io',
    'actual_normal_names_present_edges', 'actual_normal_read_write_fsync_readback',
    'actual_normal_complete_inspect_27_41_37', 'actual_original_close_ebadf',
    'actual_named_fault_branch_control_flow', 'actual_external_private_temp_cleanup',
    'actual_wsl_test_runner')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw): raise OSError('short_write')
        stream.flush(); os.fsync(stream.fileno())
    if path.read_bytes() != raw: raise ValueError('snapshot_readback')


def fixed_source(name, size=None, sha=None):
    if not isinstance(name, str) or name.startswith(('/', '\\')) or '..' in name.split('/'):
        raise ValueError('source_path')
    path = BASE / name
    before = path.stat()
    limit = 40000 if size is None else size
    with path.open('rb') as stream: raw = stream.read(limit + 1)
    after = path.stat()
    fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
              'st_size','st_mtime_ns','st_ctime_ns')
    if (tuple(getattr(before,k) for k in fields) != tuple(getattr(after,k) for k in fields) or
            len(raw) > limit or len(raw) != before.st_size or
            size is not None and len(raw) != size or sha is not None and digest(raw) != sha):
        raise ValueError('source_pin')
    return raw


def literal(tree, name):
    rows = [node.value for node in tree.body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(rows) != 1: raise ValueError('stage_literal')
    return ast.literal_eval(rows[0])


def collect_payloads(sources):
    ordinary, assets, manifest = [json.loads(sources[path]) for path, size, sha in CATALOGS]
    if (ordinary['schema'] != 'p011-formal-send-v1-ordinary-source-catalog' or
            ordinary['source_count'] != 32 or len(ordinary['sources']) != 32 or
            len(ordinary['startup_sources']) != 3 or len(ordinary['helper_sources']) != 3 or
            assets['sender_source_count'] != 25 or len(assets['sender_sources']) != 25 or
            assets['observer_source_count'] != 41 or len(assets['observer_sources']) != 41 or
            manifest['schema'] != 'p011-go-send-assets-v76' or len(manifest['sources']) != 25 or
            manifest['sources'] != [[r['module'],r['bytes'],r['sha256']] for r in assets['sender_sources']]):
        raise ValueError('catalog_shape')
    tree = ast.parse(sources[STAGE], feature_version=(3,5))
    groups = (
        ('sender',assets['sender_root'],assets['sender_sources']+[assets['sender_manifest'],assets['wpa']]),
        ('observer',assets['observer_root'],assets['observer_sources']),
        ('ordinary','/var/volatile/tmp/p011-mta-formal-send-v1',
         [r for r in ordinary['sources'] if not r['reused_sender_asset']]+
         ordinary['startup_sources']+ordinary['helper_sources']),
    )
    mapped, all_targets = [], set()
    for group, total in zip(groups,TOTALS):
        profile, root, rows = group
        pins = []
        for row in rows:
            target = row.get('physical_target',row['target'])
            if target in all_targets or not target.startswith(root+'/'): raise ValueError('target_shape')
            relative = target[len(root)+1:]
            if (len(relative.split('/')) not in (1,2) or
                    any(re.fullmatch('[A-Za-z0-9_.-]{1,80}',p) is None for p in relative.split('/'))):
                raise ValueError('target_shape')
            mode = row.get('mode','0400')
            mode = int(mode,8) if type(mode) is str else mode
            if mode not in (0o400,0o500,0o700): raise ValueError('target_mode')
            raw = fixed_source(row['source'],row['bytes'],row['sha256'])
            if row['source'] in sources and sources[row['source']] != raw: raise ValueError('source_changed')
            sources[row['source']] = raw
            pins.append((relative,len(raw),digest(raw),mode)); all_targets.add(target)
        if profile != total[0] or len(pins) != total[1] or sum(p[1] for p in pins) != total[2]:
            raise ValueError('fixed_profile_total')
        if not 0 < total[2] <= 4*1024*1024: raise ValueError('fixed_batch_limit')
        mapped.append((profile,root,tuple(pins)))
    if (tuple(mapped) != literal(tree,'PROFILE_FILES') or literal(tree,'PROFILE_TOTALS') != TOTALS or
            literal(tree,'MAX_SECONDS') != 120.0 or len(all_targets) != 105 or len(sources) != 91):
        raise ValueError('fixed_mapping')


def linux_path(path):
    value = path.absolute().as_posix()
    if not value.startswith('D:/project/P011/working/MtaP011-v0.1/results/'):
        raise ValueError('fixed_wsl_snapshot_path')
    return '/mnt/d/' + value[3:]


def main():
    if sys.argv[1:]: raise ValueError('fixed_HOST_only')
    out = BASE/'results'/('formal-send-stage-linux-io-host-'+
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:8])
    out.mkdir(parents=True,exist_ok=False)
    sources, stdout, stderr = {}, b'', b''
    report = dict(schema='p011-formal-send-stage-linux-io-host-v1',passed=False,
        host_exit=None,child_exit=None,remote_exit=None,checker_exit=None,new_methods=1,
        executed_methods=0,old_methods=0,contracts=0,case_count=0,exact_case_sequence=False,
        source_count=0,source_preserved=False,profile_file_counts=[27,41,37],
        profile_bytes=[2402458,1440449,1266713],per_profile_raw_cap=4*1024*1024,
        per_profile_seconds=120.0,linux_environment=None,
        normal_uid_model=False,normal_clock_model=False,normal_permissions_model=False,
        normal_flags_model=False,normal_os_model=False,named_fault_os_proxy=True,
        named_tail_metadata_fault=True,named_tail_child_fault=True,
        named_unknown_fstat_fault=True,named_duplicate_open_fault=True,
        changed_row_inventory_fault=True,low_level_fault_pins=True,
        linux_tmp_binding_fixture=True,actual_arm_platform=False,platform_method=False,
        aliases_method=False,parents_method=False,service_parents_method=False,stage_method=False,
        payload_method=False,boot=False,owner=False,helper_exec=False,native=False,rf=False,
        ui=False,device=False,phone=False,send_verified=False,receive_verified=False,
        restoration_verified=False,production_admitted=False,error=None)
    for name in ACTUAL_FIELDS: report[name]=False
    try:
        for name in (TEST,SELF,CMD,STAGE):
            pin=PINS.get(name)
            sources[name]=fixed_source(name,*(pin or (None,None)))
        for name,size,sha in CATALOGS: sources[name]=fixed_source(name,size,sha)
        collect_payloads(sources)
        inventory={}
        for name,raw in sources.items():
            save(out/'private-inputs'/name,raw)
            inventory[name]=dict(bytes=len(raw),sha256=digest(raw))
        save(out/'private-inputs.json',(json.dumps(inventory,sort_keys=True,indent=2)+'\n').encode('ascii'))
        argv=['wsl.exe','-d','kali-linux','-u','root','--exec','python3','-I','-B',
              linux_path(out/'private-inputs'/TEST)]
        save(out/'private-launch.json',(json.dumps(argv)+'\n').encode('ascii'))
        try:
            child=subprocess.run(argv,cwd=str(out/'private-inputs'),stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90,check=False)
            stdout,stderr=child.stdout,child.stderr
            report['host_exit']=child.returncode  # Real outer WSL runner exit.
        except subprocess.TimeoutExpired as error:
            stdout,stderr=error.stdout or b'',error.stderr or b''
            report['error']='timeout'
        derived=stdout.replace(b'\r\r\n',b'\n').replace(b'\r\n',b'\n')
        marks=re.findall(rb'^SEND_STAGE_LINUX_CONTRACTS=([0-9]+)$',derived,re.M)
        cases=re.findall(rb'^HOST_SEND_STAGE_LINUX_CASE=([a-z0-9_]+)$',derived,re.M)
        exits=re.findall(rb'^LINUX_STAGE_CHILD_EXIT=([01])$',derived,re.M)
        environments=re.findall(rb'^LINUX_STAGE_ENV=(\{[^\n]+\})$',derived,re.M)
        report['contracts']=int(marks[0]) if len(marks)==1 else 0
        report['case_count']=len(cases)
        report['exact_case_sequence']=tuple(v.decode('ascii') for v in cases)==CASES
        report['child_exit']=int(exits[0]) if len(exits)==1 else None
        if len(environments)==1: report['linux_environment']=json.loads(environments[0])
    except Exception as error:
        report['error']=type(error).__name__
        save(out/'private-error.txt',str(error).encode('utf-8'))
    for name,raw in (('stdout',stdout),('stderr',stderr)):
        save(out/(name+'.raw'),raw)
        report[name+'_bytes'],report[name+'_sha256']=len(raw),digest(raw)
    save(out/'host-exit.raw',(str(report['host_exit'])+'\n').encode('ascii'))
    save(out/'child-exit.raw',(str(report['child_exit'])+'\n').encode('ascii'))
    save(out/'remote-exit.raw',b'NOT_RUN_DEVICE\n')
    report['source_count']=len(sources)
    try:
        report['source_preserved']=(len(sources)==91 and all((BASE/name).read_bytes()==raw and
            (out/'private-inputs'/name).read_bytes()==raw for name,raw in sources.items()))
    except Exception as error:
        if report['error'] is None: report['error']=type(error).__name__
        save(out/'private-preservation-error.txt',str(error).encode('utf-8'))
    expected_env=dict(platform='linux',machine='x86_64',python=[3,13,12],euid=0,egid=0,
        nofollow=131072,cloexec=524288,arm_platform_checked=False,platform_method_called=False)
    derived_err=stderr.replace(b'\r\r\n',b'\n').replace(b'\r\n',b'\n')
    report['passed']=(report['host_exit']==0 and report['child_exit']==0 and report['error'] is None and
        report['source_preserved'] and report['contracts']==20 and report['case_count']==20 and
        report['exact_case_sequence'] and report['linux_environment']==expected_env and
        len(re.findall(rb'^Ran 1 test in [0-9.]+s$',derived_err,re.M))==1 and
        len(re.findall(rb'^OK$',derived_err,re.M))==1 and
        stdout.count(b'LINUX_STAGE_FIXED_PAYLOAD_ROWS=105')==1 and
        stdout.count(b'LINUX_STAGE_FIXED_PROFILE_FILES=27,41,37')==1)
    if report['passed']:
        report['executed_methods']=1
        for name in ACTUAL_FIELDS: report[name]=True
    report['checker_exit']=0 if report['passed'] else 1
    result=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode('ascii')
    note=(b'One NEW HOST method / 20 cases loads the frozen FixedStage definitions '
        b'and calls its real low-level constructor/context/clock/open/close/directory '
        b'edges/names/present/read/inspect/create/write methods in a fresh, identity-'
        b'checked Linux /tmp child. Normal branches use actual x86_64 Linux root, '
        b'uid/gid/modes, O_NOFOLLOW/O_CLOEXEC/O_EXCL, openat/dir-FD IO, monotonic '
        b'clock, current-thread, writes/fsync/readback and EBADF. Real fixed '
        b'27/41/37 payloads are opaque data; each original profile stays <=4MiB '
        b'and <=120 seconds. Each complete tree is re-inspected without writes '
        b'or full-metadata changes. Four named adversarial branches use FaultOS '
        b'for tail file/child mutation, unknown fstat and duplicate open; all '
        b'other proxy methods forward real os. Changed row-FD is an explicit '
        b'inventory fault. Unknown/collision production refs stay retained and '
        b'unclosed; an external HOST-only owner closes only its separately held '
        b'exact FD identities, then removes only its verified new temp. Two-file '
        b'fault inspections use low-level test pins, not a replaced profile. '
        b'Actual flags stay false until the complete strict new method passes. '
        b'No ARM/platform(), aliases(), parents(), service_parents(), payload(), '
        b'stage(), Boot, Owner, asset Python/native/helper execution, Native, RF, '
        b'UI, P011, phone, send or restoration. No old test/checker is invoked. '
        b'WSL root is explicit; no Docker, install or network operation. All 91 '
        b'fixed input snapshots, launch argv, raw stdout/stderr, child/WSL/checker '
        b'exits and private errors stay PRIVATE; remote device is NOT_RUN. '
        b'This ZIP has only non-identifying result.json and README.txt.\n')
    save(out/'result.json',result); save(out/'README.txt',note)
    save(out/'checker-exit.raw',(str(report['checker_exit'])+'\n').encode('ascii'))
    bundle=out/'public-result.zip'
    with zipfile.ZipFile(bundle,'x',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json',result); archive.writestr('README.txt',note)
    with zipfile.ZipFile(bundle) as archive:
        if (archive.namelist()!=['result.json','README.txt'] or archive.testzip() is not None or
                archive.read('result.json')!=result or archive.read('README.txt')!=note):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'],result_dir=str(out),
        zip_bytes=bundle.stat().st_size,zip_sha256=digest(bundle.read_bytes())),sort_keys=True))
    return report['checker_exit']


if __name__=='__main__':
    raise SystemExit(main())
