"""Independent, read-only verification of the one already archived GO64.

Default SOURCE only. --verify-current reads the fixed archive/journal under
their existing locks; it cannot move, delete, rewrite or resume any session.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import types
import zipfile

BASE=Path(__file__).resolve().parents[1]
OLD=('host/device_go_pending_readonly_20261004.py',26460,
     '97ab846cc8e9fa822d145cc5fb73dadddb4ccda8ebfe94c894c0fa7a15cc89c3')
EXECUTION=BASE/'results/go64-single-retirement-20261004-161656-9c9facf4'
REMOTE_PIN=(760778,'1a08e4891bad784ffdc4e9ec1a37e52f4941b0a9741b62b6eba2b7f9fcc9812f')
ARCHIVE='go-pending.archived-20261004-v1'


def digest(raw):return hashlib.sha256(raw).hexdigest()
def require(value,code):
    if value is not True:raise ValueError(code)


def previous_execution():
    private=EXECUTION/'private-raw'
    saved=(private/'remote-result.json').read_bytes()
    require((len(saved),digest(saved))==REMOTE_PIN,'execution_result_pin')
    # Audit the independently retained original output, not just a public flag.
    require((private/'01-go64-retire-single.host-exit').read_bytes()==b'0','original_host_exit')
    require((private/'01-go64-retire-single.stderr.raw').read_bytes()==b'','original_stderr')
    stdout=(private/'01-go64-retire-single.stdout.raw').read_bytes()
    require(len(stdout)<=2097152,'original_stdout_bound')
    lines=stdout.decode('ascii').replace('\r\r\n','\n').replace('\r\n','\n').splitlines()
    require(lines.count('MTA_REMOTE_OK')==1 and lines.count('MTA_REMOTE_EXIT=0')==1,'original_remote_exit')
    results=[line[7:] for line in lines if line.startswith('RESULT=')]
    require(len(results)==1,'original_result_count')
    original=ast.literal_eval(results[0]);admin=original['administrative']
    require(original['complete']is True and original['local_fds_closed']is True and
            admin['rename_outcome_known']is True and admin['original_inode_archived']is True and
            admin['source_pending_absent']is True and admin['original_journal_unchanged']is True,
            'original_execution_incomplete')
    rows=[r for r in original['rows'] if r['role']=='archive_readback']
    require(len(rows)==1 and rows[0]['closed']is True and rows[0]['unknown']is False,'archive_readback_inventory')
    metadata=rows[0]['metadata']
    require(metadata[:8]==original['before']['pending_metadata'][:8],'original_inode_identity')
    return metadata,saved,stdout


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-current',action='store_true')
    args=parser.parse_args()
    raw=(BASE/OLD[0]).read_bytes()
    require((len(raw),digest(raw))==OLD[1:],'old_source_pin')
    old=types.ModuleType('fixed_original_readonly');old.__file__=str(BASE/OLD[0])
    exec(compile(raw,old.__file__,'exec'),old.__dict__)
    inputs=old.fixed_inputs();config=old.fixed_config(inputs)
    metadata,saved,original_stdout=previous_execution()
    body=old.BODY
    pending="pending_path=root+'/p011-mta-p2p-device.pending'"
    hook=" lock_current();now();stage='complete'\n"
    require(body.count(pending)==body.count(hook)==1,'original_source_hooks')
    body=body.replace(pending,"source_pending_path=root+'/p011-mta-p2p-device.pending'\npending_path=run+'/'+ARCHIVE_NAME")
    body=body.replace(hook,""" stage='post_archive_verify'
 if result['before']['pending_metadata']!=ARCHIVE_METADATA or result['after']['pending_metadata']!=ARCHIVE_METADATA:fail('archived_inode_changed')
 if path_state(source_pending_path)is not None:fail('source_pending_reappeared')
 lock_current()
 if path_state(source_pending_path)is not None:fail('source_pending_reappeared')
 result['post_archive_verified']=True
"""+hook)
    original=old.source(inputs,config)
    require(original.endswith(old.BODY),'original_suffix')
    source=original[:-len(old.BODY)]+'ARCHIVE_NAME='+repr(ARCHIVE)+'\nARCHIVE_METADATA='+repr(metadata)+'\n'+body
    ast.parse(source,feature_version=(3,5))
    require(len(source.encode('ascii'))<=65536,'source_budget')
    out=BASE/'results'/('go64-archive-postcheck-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    private=out/'private-raw';private.mkdir(parents=True,exist_ok=False)
    own=Path(__file__).read_bytes();(private/'host-source.py').write_bytes(own)
    (private/'original-readonly-source.py').write_bytes(raw)
    (private/'archiving-remote-result.json').write_bytes(saved)
    (private/'archiving-stdout.raw').write_bytes(original_stdout)
    (private/'target-source.py').write_bytes(source.encode('ascii'))
    value=None;error=None;transport_ok=False
    if args.verify_current:
        try:
            transport=types.ModuleType('fixed_postcheck_transport');transport.__file__=str(BASE/'host/device_probe.py')
            exec(compile(inputs[BASE/'host/device_probe.py'],transport.__file__,'exec'),transport.__dict__)
            adb_raw=transport.ADB.read_bytes();value=transport.Adb(private).python('archive-postcheck',source,timeout=45)
            transport_ok=transport.ADB.read_bytes()==adb_raw
        except BaseException as failure:
            error=type(failure).__name__;(private/'host-error.txt').write_text(error+'\n',encoding='ascii')
    unchanged=own==Path(__file__).read_bytes() and raw==(BASE/OLD[0]).read_bytes() and old.fixed_inputs()==inputs
    observed=type(value)is dict
    report=dict(schema='p011-go64-archive-postcheck-v1',mode='device' if args.verify_current else 'source',
        source_preserved=unchanged,source_ast_verified=True,device_invoked=args.verify_current,host_error=error,
        transport_unchanged=transport_ok,target_complete=observed and value.get('complete')is True,
        byte_exact_archived_original_and_journal=observed and value.get('record_match')is True,
        archived_original_inode_unchanged=observed and value.get('post_archive_verified')is True,
        original_journal_metadata_unchanged=observed and value.get('record_match')is True,
        records_stable_twice=observed and value.get('records_unchanged')is True,
        original_actors_absent_twice=observed and value.get('actors_paths_absent')is True,
        same_original_boot=observed and value.get('same_boot')is True,
        source_pending_absent_twice=observed and value.get('post_archive_verified')is True,
        actual_local_fds_closed=observed and value.get('local_fds_closed')is True,
        device_mutations=False,radio_operations=False,client_history_touched=False,
        original_restored_receipt_issued=False,full_network_restore_verified=False,
        post_stock_network_observed=False,receive_available=False,phone_tested=False,private_raw_included=False)
    required=('target_complete','byte_exact_archived_original_and_journal','archived_original_inode_unchanged',
        'original_journal_metadata_unchanged','records_stable_twice','original_actors_absent_twice',
        'same_original_boot','source_pending_absent_twice','actual_local_fds_closed','transport_unchanged')
    report['passed']=unchanged and error is None and (not args.verify_current or all(report[k] for k in required))
    result=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode('ascii')
    readme=b'Independent post-archive readonly check under the original existing locks. Original archive inode/metadata/bytes, untouched journal and source absence; no RF, old restored receipt or new receive grant. Stock/network was not observed by this separate postcheck. Raw originals remain private.\n'
    (out/'result.json').write_bytes(result);(out/'README.txt').write_bytes(readme)
    with zipfile.ZipFile(out/'public-result.zip','x',zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json',result);bundle.writestr('README.txt',readme)
    print(json.dumps(dict(directory=str(out),result=report),sort_keys=True))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
