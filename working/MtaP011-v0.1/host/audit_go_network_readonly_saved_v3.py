"""Audit original saved network DATA; no ADB, execution, record write or grant.

The failed HOST wrapper tried to literal-parse an unused native structural-key
repr. This audit substitutes only its known outside-string renderings, then
discards precisely those two unused fields. The original raw stays untouched.
All actual network fields, comparisons and FD inventory remain original data.
"""
import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import zipfile

BASE = Path(__file__).resolve().parents[1]
ORIGINAL = BASE/'results/go-retirement-network-readonly-20261004-155446-b7b5f34e'
OLD = BASE/'results/go-active-budget-v64-20261002-213823-170ca3c0/private-raw/native-private.json'
FIELDS = ('boot','stock_hashes','stock_actors','station','station_state_sha',
          'station_frequency','interfaces','ipv4','ipv6_addresses','ipv6_routes','station_completed')


def require(value, code):
    if value is not True: raise ValueError(code)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def parse_unused_native_repr(text):
    output=[];i=0;routes=rules=0
    while i < len(text):
        if text[i] in ('"',"'"):
            quote=text[i];j=i+1
            while j<len(text):
                if text[j]=='\\':j+=2;continue
                if text[j]==quote:break
                j+=1
            require(j<len(text),'raw_quote')
            output.append(text[i:j+1]);i=j+1;continue
        if text.startswith('<RouteRecord private>',i):
            output.append("'UNPARSED_ROUTE_RECORD_REPR'");i+=len('<RouteRecord private>');routes+=1;continue
        match=re.match(r'RuleRecord\(priority=[0-9]{1,10}, table=[0-9]{1,10}\)',text[i:])
        if match:
            output.append("'UNPARSED_RULE_RECORD_REPR'");i+=len(match.group());rules+=1;continue
        output.append(text[i]);i+=1
    require((routes,rules)==(18,6),'unused_rendering_counts')
    value=ast.literal_eval(''.join(output))
    require(len(value['passes'])==2,'actual_pass_count')
    for row in value['passes']:
        require(set(row)=={'data','parents','pin_metadata','ipv4_structural'},'pass_shape')
        unused=row.pop('ipv4_structural')
        require(unused[1]==('UNPARSED_ROUTE_RECORD_REPR',)*9 and
                unused[2]==('UNPARSED_RULE_RECORD_REPR',)*3,'unused_field_only')
    require('UNPARSED_' not in repr(value),'no_native_placeholder_in_actual_data')
    return value


def actor_core(row): return tuple(row[key] for key in ('pid','start','exe','argv_sha'))
def actor_tasks(row): return sorted(tuple(task[:2]) for task in row['tasks'])
def ipv6_configuration(rows): return sorted(tuple(row[:6]+row[8:]) for row in rows)


def main():
    private=ORIGINAL/'private-raw'
    raw=(private/'01-go-retirement-network-readonly.stdout.raw').read_bytes()
    require((private/'01-go-retirement-network-readonly.host-exit').read_bytes()==b'0','original_adb_exit')
    require((private/'01-go-retirement-network-readonly.stderr.raw').read_bytes()==b'','original_stderr')
    text=raw.decode('utf-8').replace('\r\r\n','\n').replace('\r\n','\n')
    lines=text.splitlines()
    require(lines.count('MTA_REMOTE_OK')==lines.count('MTA_REMOTE_EXIT=0')==1,'original_remote_exit')
    results=[line[7:] for line in lines if line.startswith('RESULT=')]
    require(len(results)==1,'original_result')
    actual=parse_unused_native_repr(results[0])
    original_report=json.loads((ORIGINAL/'result.json').read_bytes())
    require(original_report['host_error_observed'] is True and original_report['diagnostic_complete'] is False,
            'preserve_original_host_fail')
    target=(private/'target-source.py').read_bytes()
    require(len(target)==original_report['target_source_bytes'] and sha(target)==original_report['target_source_sha256'],
            'original_target_source')
    require((ORIGINAL/'private-inputs/host-source.py').read_bytes()==
            (BASE/'host/device_go_retirement_network_readonly_v3.py').read_bytes(),'original_host_source')
    inventory=json.loads((private/'inputs.json').read_bytes())
    require(len(inventory)==6,'input_count')
    for pin in inventory:
        saved=(ORIGINAL/'private-inputs'/pin['name']).read_bytes()
        require(len(saved)==pin['bytes'] and sha(saved)==pin['sha256'],'saved_input_identity')
    old=json.loads(OLD.read_bytes())['process']['journal']['baseline']
    require(actual['complete'] is True and actual['stage']=='complete' and actual['reason']=='ok' and
            actual['current_baseline_stable'] is True and actual['old_record_unchanged'] is True and
            actual['resource_inventory_closed'] is True and not actual['close_errors'],'original_target_complete')
    all_rows=actual['fd_rows']+actual['socket_rows']+actual['child_rows']+actual['pipe_rows']
    require(all(row['closed'] is True and row['unknown'] is False for row in all_rows),'actual_resource_inventory')
    current=actual['passes'][1]['data']
    comparison=actual['historical_data_comparison']
    require(set(comparison)==set(FIELDS),'original_comparison_shape')
    original_actors={row['exe'].rsplit('/',1)[-1]:row for row in old['stock_actors']}
    current_actors={row['exe'].rsplit('/',1)[-1]:row for row in current['stock_actors']}
    require(len(original_actors)==len(current_actors)==6 and set(original_actors)==set(current_actors),'actor_roles')
    actors=[dict(role=role,core_identity_equal=actor_core(original_actors[role])==actor_core(current_actors[role]),
                 task_identity_equal=actor_tasks(original_actors[role])==actor_tasks(current_actors[role]),
                 historical_task_count=len(original_actors[role]['tasks']),current_task_count=len(current_actors[role]['tasks']))
            for role in sorted(original_actors)]
    report=dict(schema='p011-saved-go-network-data-audit-v3',saved_device_data_audit_passed=True,
        original_host_wrapper_failed=True,original_host_failure_preserved=True,original_adb_host_exit=0,original_remote_exit=0,
        original_target_complete=True,current_baseline_stable=True,old_record_unchanged=True,
        original_resource_inventory_closed=True,fd_count=len(actual['fd_rows']),socket_count=len(actual['socket_rows']),
        child_count=len(actual['child_rows']),pipe_count=len(actual['pipe_rows']),cleanup_errors=0,
        historical_data_comparison=comparison,historical_full_data_equal=all(comparison.values()),
        stock_actor_comparison=actors,
        ipv6_full_rows_equal=old['ipv6_routes']==current['ipv6_routes'],
        ipv6_configuration_excluding_use_ref_counters_equal=ipv6_configuration(old['ipv6_routes'])==ipv6_configuration(current['ipv6_routes']),
        ipv6_historical_route_count=len(old['ipv6_routes']),ipv6_current_route_count=len(current['ipv6_routes']),
        non_netdev_wdev_count=sum(row['ifindex'] is None for row in current['interfaces']),
        p2p_iftype_count=sum(row['iftype'] in (8,9,10) for row in current['interfaces']),
        ipv4_address_count=len(current['ipv4']['addresses']),ipv4_route_count=len(current['ipv4']['routes']),
        ipv4_rule_count=len(current['ipv4']['rules']),wifi_completed=current['station_completed'],
        unused_native_repr_fields_discarded=2,raw_stdout_sha256=sha(raw),target_source_sha256=sha(target),
        device_invoked=False,tests_replayed=False,target_records_changed=False,old_session_terminalized=False,
        restoration_grant_issued=False,original_snapshot_key_verified=False,full_network_restore_verified=False,
        phone_tested=False,private_raw_included=False)
    out=BASE/'results'/('go-network-saved-audit-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))
    out.mkdir(exist_ok=False)
    report_raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode('ascii')
    readme=(b'Read-only audit of existing device raw. No target/test replay. Original HOST parser failure is unchanged.\n'
            b'Only known outside-string native renderings in two unused structural-key fields are substituted and discarded; actual scalar/data/FD fields remain original. No original native key or closure/restore/admission authority is reconstructed.\n'
            b'Current/historical configuration and actor differences are DATA, not authorization to retire a record. Source/raw/input originals stay private.\n')
    (out/'result.json').write_bytes(report_raw);(out/'README.txt').write_bytes(readme)
    with zipfile.ZipFile(out/'public-result.zip','x',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json',report_raw);archive.writestr('README.txt',readme)
    with zipfile.ZipFile(out/'public-result.zip') as archive:
        require(archive.namelist()==['result.json','README.txt'] and archive.testzip() is None and
                archive.read('result.json')==report_raw and archive.read('README.txt')==readme,'zip_exact')
    print(json.dumps(dict(directory=str(out),result=report),sort_keys=True))


if __name__=='__main__': main()
