"""Whitelist-only evidence ZIP; never archives private-raw or user files."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import zipfile

BASE=Path(__file__).resolve().parents[1]
ROOT=BASE.parents[1]


def latest(parent,pattern,report='result.json',name_pattern=None):
    rows=[p for p in parent.glob(pattern) if p.is_dir() and (p/report).is_file()
          and (name_pattern is None or re.fullmatch(name_pattern,p.name))]
    return sorted(rows)[-1] if rows else None


def collect_members():
    """Reviewed public outputs only. Never walk a raw/candidate/user tree."""
    members=[]
    for name in ['README.md','GOAL.md','CURRENT_STATUS.md']:
        members.append((BASE/name,'documents/'+name))
    for name in ['NETWORK_BACKEND.md','SERVICE_REVIEW.md','SENDER_FLOW_REVIEW.md',
                 'P2P_TRIAL_PLAN.md','P2P_TRIAL_V2_PLAN.md','P2P_TRIAL_V3_PLAN.md','P2P_TRIAL_V4_PLAN.md',
                 'P2P_TRIAL_V5_PLAN.md','WORKER_IMPLEMENTATION_NEXT.md',
                 'SEND_INTEGRATION_PLAN.md','RECEIVE_P2P_PLAN.md',
                 'OWNED_IP_CORE.md','OWNED_IP_LEASE_REVIEW.md','DHCP_SOCKET_REVIEW.md',
                 'P2P_IP_V6_DIAG_REVIEW.md','P2P_TRIAL_V6DIAG_PLAN.md','SCOPED_SOCKET_REVIEW.md',
                 'CANDIDATE_PERMISSIONS_REVIEW.md','P2P_V6DIAG_PERMISSIONS_ENTRY.md',
                 'TRANSPORT_LIFECYCLE_REVIEW.md','P2P_IP_V7_L3_DIAG_REVIEW.md',
                 'DHCP_CLIENT_CORE_REVIEW.md','P2P_TRIAL_V7_L3_PLAN.md',
                 'TRANSFER_SESSION_REVIEW.md','UDP_LOOPBACK_REVIEW.md',
                 'P2P_IP_V8_ROUTE_DIAG_REVIEW.md','P2P_TRIAL_V8_ROUTE_PLAN.md',
                 'DHCP_CLIENT_SOCKET_REVIEW.md','P2P_IP_V9_MROUTE_REVIEW.md',
                 'P2P_CLIENT_NATIVE_NEXT_REVIEW.md','STATE_SESSION_INTEGRATION_REVIEW.md',
                 'P2P_TRIAL_V9_MROUTE_PLAN.md','P2P_V9_PREFLIGHT_TIMEOUT_REVIEW.md',
                 'P2P_CLIENT_CTRL_REVIEW.md','TTY_ACTOR_READONLY_REVIEW.md',
                 'P2P_TRIAL_V9_BOUNDED_PLAN.md','P2P_CLIENT_INIT_OWNER_PLAN.md',
                 'STATE_DEVICE_SMOKE_NEXT_REVIEW.md','IP_RECEIPT_RECOVERY_REVIEW.md',
                 'P2P_V9_RESTORE_READONLY_REVIEW.md','P2P_V9_091400_FAILURE_ANALYSIS.md',
                 'P2P_V9_CURRENT_TRIAGE_REVIEW.md','STATE_SMOKE_READONLY_ENTRY_REVIEW.md',
                 'LATEST_CHECKPOINT.md','CLIENT_CAPS_DECODER_REVIEW.md',
                 'STATE_SMOKE_OBSERVER_REVIEW.md','P2P_CLIENT_INIT_IMPLEMENTATION_REVIEW.md',
                 'CLIENT_CAPS_TRANSPORT_REVIEW.md','CLIENT_JOURNAL_CODEC_REVIEW.md',
                 'CLIENT_PROC_READER_REVIEW.md','DEVICE_CLIENT_CAPS_READONLY_REVIEW.md',
                 'CLIENT_FILES_REVIEW.md','CLIENT_FILES_LINUX_HOST_CHECK.md',
                 'CLIENT_STORE_IMPLEMENTATION_NEXT.md','CLIENT_COORDINATION_REVIEW.md',
                 'CLIENT_PREPARATION_STORE_REVIEW.md','FILE_SELECTION_LIFECYCLE_REVIEW.md',
                 'SEND_WORKER_REVIEW.md','TRANSFER_SESSION_DIRECTION_REVIEW.md',
                 'SCAN_HANDOFF_REVIEW.md','STATE_SEND_INTEGRATION_REVIEW.md',
                 'CLIENT_STORE_FINISH_DECISION.md','CLIENT_FINISH_CONTRACT_REVIEW.md',
                 'CLIENT_PENDING_FILE_REVIEW.md','P2P_ASSOCIATION_REVIEW.md',
                 'CLIENT_PROCESS_OWNER_REVIEW.md','CLIENT_OWNED_MARKER_REVIEW.md',
                 'CLIENT_JOURNAL_TRANSACTION_REVIEW.md',
                 'CLIENT_JOURNAL_TRANSACTION_LINUX_CHECK_REVIEW.md',
                 'CLIENT_JOURNAL_HANDOFF_REVIEW.md','CLIENT_PENDING_CLEAR_REVIEW.md',
                 'DURABLE_CLIENT_STORE_REVIEW.md','CLIENT_BASELINE_REVIEW.md',
                 'CLIENT_DURABLE_STORE_LINUX_CHECK_REVIEW.md',
                 'CLIENT_LAUNCH_REGISTRATION_REVIEW.md',
                 'CLIENT_LAUNCH_REGISTRATION_LINUX_CHECK_REVIEW.md',
                 'CLIENT_WPA_STATUS_AUTH_NEXT.md']:
        path=BASE/'docs'/name
        if path.is_file():members.append((path,'documents/'+name))
    for label,folder in [('host',latest(BASE/'results','host-*',
                                       name_pattern=r'host-[0-9]{8}-[0-9]{6}-[0-9a-f]{6}')),
                         ('native-build',latest(BASE/'results','native-build-*')),
                         ('device-readonly',latest(ROOT/'logs','MtaP011-Readonly-*')),
                         ('device-runtime',latest(ROOT/'logs','MtaP011-RuntimeSmoke-*')),
                         ('device-ui',latest(ROOT/'logs','MtaP011-DeviceUi-*')),
                         ('device-bluez',latest(ROOT/'logs','MtaP011-BluezTrial-*')),
                         ('device-prepare',latest(ROOT/'logs','MtaP011-NetworkPrepare-*')),
                         ('device-tls',latest(ROOT/'logs','MtaP011-DeviceTls-*')),
                         ('device-p2p',latest(ROOT/'logs','MtaP011-DeviceP2p-*')),
                         ('device-p2p-v2',latest(ROOT/'logs','MtaP011-DeviceP2pV2-*')),
                         ('device-p2p-v3',latest(ROOT/'logs','MtaP011-DeviceP2pV3-*')),
                         ('device-p2p-v4',latest(ROOT/'logs','MtaP011-DeviceP2pV4-*')),
                         ('device-owned-cleanup',latest(ROOT/'logs','MtaP011-OwnedStaRecovery-*')),
                         ('device-integration',latest(ROOT/'logs','MtaP011-ToolboxUi-*'))]:
        if folder:
            members.append((folder/'result.json',label+'/result.json'))
            if label in ('device-p2p-v2','device-p2p-v3','device-p2p-v4'):
                members.append((folder/'README.txt',label+'/README.txt'))
            if label=='host':members.append((folder/'unittest.txt','host/unittest.txt'))
            if label in ('device-ui','device-integration'):
                for path in sorted((folder/'screens').glob('*.png')):
                    if re.match(r'^[0-9]{2}-[A-Za-z0-9_-]+\.png$',path.name):
                        members.append((path,label+'/screens/'+path.name))
    # These reviewed historical events must not be replaced by a newer PASS.
    for label,relative,filenames in [
            ('device-p2p-v3-warm','logs/MtaP011-DeviceP2pV3-20261001-022112-fc590b0e',('result.json','README.txt')),
            ('device-normal-reboot-initial','logs/MtaP011-NormalReboot-20261001-023005-d1bbea10',('result.json',)),
            ('device-boot-readonly','logs/MtaP011-BootReadOnly-20261001-023304-9c8871df',('result.json',)),
            ('device-spawn-readonly','logs/MtaP011-SpawnReadOnly-20261001-024645-8ad3725d',('result.json',)),
            ('device-wpa-config-norf','logs/MtaP011-WpaConfigNoRf-20261001-025636-5a66dea7',('result.json','README.txt')),
            ('device-wpa-version-initial','logs/MtaP011-WpaVersionNoRf-20261001-025014-32f57de4',('result.json',)),
            ('device-ip-dump-readonly','logs/MtaP011-IpDumpReadOnly-20261001-032317-adba0ac0',('result.json',)),
            ('device-ip-core-readonly-initial','logs/MtaP011-IpCoreReadOnly-20261001-034723-58f50b59',('result.json','README.txt')),
            ('device-ip-core-readonly-reviewed','logs/MtaP011-IpCoreReadOnly-20261001-035650-66a4c890',('result.json','README.txt')),
            ('device-p2p-v5-initial-failure','logs/MtaP011-DeviceP2pV5-20261001-044609-c53555d6',('result.json','README.txt')),
            ('device-v6diag-admission-failure','logs/MtaP011-DeviceP2pV6Diag-20261001-053019-ffaa543c',('result.json','README.txt')),
            ('device-prior-journal-readonly','logs/MtaP011-PriorJournalReadOnly-20261001-054328-59c5c157',('result.json','README.txt')),
            ('device-candidate-permissions-readonly','logs/MtaP011-CandidatePermissionsReadOnly-20261001-055734-dd922b01',('result.json','README.txt')),
            ('device-candidate-permissions-normalize','logs/MtaP011-CandidatePermissionsNormalize-20261001-060853-204a0e0a',('result.json','README.txt')),
            ('device-v6diag-permissions-entry','logs/MtaP011-DeviceP2pV6DiagPermissions-20261001-061551-48fbed57',('result.json','README.txt')),
            ('device-v7-l3diag-failure','logs/MtaP011-DeviceP2pV7L3Diag-20261001-072210-d0ad939a',('result.json','README.txt')),
            ('device-v8-route-diagnostic-failure','logs/MtaP011-DeviceP2pV8RouteDiag-20261001-075353-9ad31b4d',('result.json','README.txt')),
            ('device-v9-preflight-timeout','logs/MtaP011-DeviceP2pV9MRoute-20261001-082419-8c70df17',('result.json','README.txt')),
            ('device-tty-actor-readonly','logs/MtaP011-TtyActorReadOnly-20261001-084503-4abc3a74',('result.json','README.txt')),
            ('device-v9-bounded-readonly','logs/MtaP011-DeviceP2pV9Bounded-20261001-084730-3b89eb62',('result.json','README.txt')),
            ('device-v9-bounded-functional-failure','logs/MtaP011-DeviceP2pV9Bounded-20261001-084811-e064eae6',('result.json','README.txt')),
            ('device-v9-restore-readonly-failure','logs/MtaP011-V9RestoreReadOnly-20261001-091400-682a4364',('result.json','README.txt')),
            ('device-v9-current-triage-failure','logs/MtaP011-V9CurrentTriage-20261001-094137-72d4e1f2',('result.json','README.txt')),
            ('device-client-caps-initial-frame-failure','logs/MtaP011-ClientCapsReadOnly-20261001-112454-67ff5518',('result.json','README.txt')),
            ('device-client-caps-reviewed-precondition-failure','logs/MtaP011-ClientCapsReadOnly-20261001-113255-3acb18fc',('result.json','README.txt')),
            ('device-current-sysfs-readonly','logs/MtaP011-CurrentSysfsReadOnly-20261001-151948-152166',('result.json','README.txt')),
            ('device-file-only-target-selection-failure','logs/MtaP011-WpaCliFileOnly-20261001-172839-376481',('result.json','README.txt')),
            ('device-udp-loopback-initial-failure','logs/MtaP011-UdpLoopback-20261001-072329-0cfa2813',('result.json','README.txt')),
            ('device-udp-loopback-reviewed','logs/MtaP011-UdpLoopback-20261001-073152-11ad27e3',('result.json','README.txt')),
            ('device-udp-api-readonly','logs/MtaP011-UdpApiReadOnly-20261001-043409-b782aaca',('result.json','README.txt'))]:
        folder=ROOT/relative
        if (folder/'result.json').is_file():
            for filename in filenames:members.append((folder/filename,label+'/'+filename))
    # This final-source component result is not the project integration suite.
    observer=BASE/'results/state-observer-host-20261001-103410-feab09'
    if (observer/'result.json').is_file():
        for name in ('result.json','README.txt'):
            members.append((observer/name,'host-state-observer-component/'+name))
    # Reviewed incremental batches are distinct from a final-source full run.
    client=BASE/'results/client-components-host-review-20261001'
    if (client/'result.json').is_file():
        for name in ('result.json','README.txt'):
            members.append((client/name,'host-client-incremental-components/'+name))
    # Actual HOST Linux self-observation and the first device failure analysis
    # have separate evidence levels and must not substitute for device caps.
    for label,relative in [
            ('host-linux-client-proc','results/client-proc-linux-host-20261001-03a573'),
            ('host-linux-client-files','results/client-files-linux-host-20261001-040520-db3f3abc9c37595f'),
            ('host-linux-client-coordination-adapter','results/client-coordination-linux-host-20261001-af12be'),
            ('host-linux-client-preparation-initial-failure','results/client-preparation-linux-host-20261001-12ae9d-initial-failure'),
            ('host-linux-client-preparation','results/client-preparation-linux-host-20261001-c6d315'),
            ('host-linux-file-selection','results/file-selection-linux-host-20261001-7b680f'),
            ('host-linux-client-pending','results/client-pending-linux-host-20261001-5b45e5'),
            ('host-linux-client-process-owner','results/client-process-owner-linux-host-20261001-69bab0'),
            ('host-client-journal-transaction-review','results/client-journal-transaction-host-review-20261001'),
            ('host-client-journal-handoff-review','results/client-journal-handoff-host-review-20261001'),
            ('host-client-durable-store-review','results/client-durable-store-host-review-20261001'),
            ('host-client-baseline-review','results/client-baseline-host-review-20261001'),
            ('host-client-durable-linux-review','results/client-durable-linux-host-review-20261001'),
            ('host-linux-client-durable-store','results/client-durable-store-linux-host-20261001-093144-3f5db4906e3669e7'),
            ('host-client-launch-registration-review','results/client-launch-registration-host-review-20261001'),
            ('host-client-launch-linux-review','results/client-launch-linux-host-review-20261001'),
            ('host-linux-client-launch-registration','results/client-launch-linux-host-20261001-102942-b9fadf630b752bc8'),
            ('host-adb-enumeration-only','results/host-adb-enumeration-only-20261001-181513'),
            ('host-linux-client-journal-transaction','results/client-journal-transaction-linux-host-20261001-075743-8344d8420325c16a'),
            ('device-client-caps-initial-analysis','results/client-caps-readonly-analysis-20261001-112454')]:
        folder=BASE/relative
        if (folder/'result.json').is_file():
            for name in ('result.json','README.txt'):
                members.append((folder/name,label+'/'+name))
    # Later identified file-only success does not replace the earlier no-target
    # failure. Never include its private transport output or future attempts.
    identified=ROOT/'logs/MtaP011-WpaCliFileOnly-20261001-182506-877184'
    if (identified/'result.json').is_file():
        for name in ('result.json','README.txt'):
            members.append((identified/name,'device-file-only-identified-ready/'+name))
    # Fixed clear increment uses Markdown README; never glob future Store results.
    clear=BASE/'results/client-pending-clear-host-review-20261001'
    if (clear/'result.json').is_file():
        for name in ('result.json','README.md'):
            members.append((clear/name,'host-client-pending-clear-review/'+name))
    # Exact reviewed HOST provenance; never select a future diagnostic candidate.
    for label,relative in [('owned-ip-host','results/owned-ip-host-20261001-043347-0e487f'),
                           ('v6-gate-diag-host','results/v6diag-host-20261001-051618-55379f'),
                           ('host-direct-entry-import-failure','results/host-20261001-063809-641096')]:
        folder=BASE/relative
        if (folder/'result.json').is_file():
            for filename in ('result.json','unittest.txt'):
                members.append((folder/filename,label+'/'+filename))
    ui=latest(BASE/'results','ui-host-*','ui-result.json') or BASE/'results/ui-host'
    for label,folder in [('ui-host',ui),('ui-assembly-host',BASE/'results/ui-assembly-host'),
                         ('ui-host-lifecycle',BASE/'results/ui-host-lifecycle-post-gates'),
                         ('toolbox-integration-ui-host',BASE/'results/toolbox-integration-ui')]:
        for path in sorted(folder.glob('*')):
            if path.is_file() and path.suffix in ('.png','.json'):
                members.append((path,label+'/'+path.name))
    for relative,label in [('results/network-host/summary.json','network-host/summary.json'),
                           ('native/WIFI_CAPABILITIES_20260930.md','documents/WIFI_CAPABILITIES.md'),
                           ('native/P2P_FIRST_TRIAL_FAILURE_REVIEW.md','documents/P2P_FIRST_TRIAL_FAILURE_REVIEW.md'),
                           ('native/OWNED_IP_DHCP_NEXT_STAGE.md','documents/OWNED_IP_DHCP_NEXT_STAGE.md'),
                           ('native/P2P_V2_REVIEW_NOTES.md','documents/P2P_V2_REVIEW_NOTES.md'),
                           ('native/P2P_V2_TRIAL_FAILURE_REVIEW.md','documents/P2P_V2_TRIAL_FAILURE_REVIEW.md'),
                           ('native/P2P_V3_DIAGNOSTIC_REVIEW.md','documents/P2P_V3_DIAGNOSTIC_REVIEW.md'),
                           ('native/P2P_V3_TRIAL_FAILURE_REVIEW.md','documents/P2P_V3_TRIAL_FAILURE_REVIEW.md'),
                           ('native/DHCP_COMPONENT_DESIGN.md','documents/DHCP_COMPONENT_DESIGN.md'),
                           ('native/tests/HOST_DHCP_EVIDENCE.md','native-host/HOST_DHCP_EVIDENCE.md'),
                           ('native/tests/HOST_P2P_V2_EVIDENCE.md','native-host/HOST_P2P_V2_EVIDENCE.md'),
                           ('native/tests/HOST_P2P_V3_EVIDENCE.md','native-host/HOST_P2P_V3_EVIDENCE.md'),
                           ('native/tests/HOST_P2P_V4_EVIDENCE.md','native-host/HOST_P2P_V4_EVIDENCE.md'),
                           ('integration/README.md','documents/TOOLBOX_INTEGRATION.md'),
                           ('results/toolbox-integration-static-20261001-final.json','integration-host/static-result.json')]:
        path=BASE/relative
        if path.is_file():members.append((path,label))
    evidence=BASE/'native/tests/HOST_EVIDENCE.md'
    if evidence.is_file():members.append((evidence,'native-host/HOST_EVIDENCE.md'))
    names=set();total=0
    for path,name in members:
        if path.is_symlink() or not path.is_file():raise ValueError('Missing or linked public evidence')
        if name in names or any(part in ('..','private','raw','out') for part in name.split('/')):
            raise ValueError('Unsafe evidence member')
        names.add(name);size=path.stat().st_size;total+=size
        if size>8*1024*1024 or total>64*1024*1024:raise ValueError('Evidence byte limit')
    return members


def main():
    members=collect_members()
    out=BASE/'results'/('MtaP011-v0.1-evidence-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')+'.zip')
    with zipfile.ZipFile(out,'x',zipfile.ZIP_DEFLATED) as bundle:
        for path,name in members:bundle.write(path,name)
        bundle.writestr('MANIFEST.json',json.dumps([{'name':name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for path,name in members],indent=2))
    with zipfile.ZipFile(out) as bundle:
        if bundle.testzip() is not None:raise RuntimeError('Evidence ZIP CRC failed')
        if any('private' in n or n.startswith('out/') for n in bundle.namelist()):raise RuntimeError('Private artifact in ZIP')
        manifest=json.loads(bundle.read('MANIFEST.json'))
        if not isinstance(manifest,list) or len(manifest)!=len(members):raise RuntimeError('Evidence manifest count failed')
        names=[row['name'] for row in manifest]
        if len(set(names))!=len(names) or set(bundle.namelist())!=set(names+['MANIFEST.json']):
            raise RuntimeError('Evidence manifest membership failed')
        for row in manifest:
            if set(row)!=set(('name','sha256')) or hashlib.sha256(bundle.read(row['name'])).hexdigest()!=row['sha256']:
                raise RuntimeError('Evidence ZIP independent SHA-256 failed')
        verified={'pass':True,'crc_verified':True,'sha256_all_members_verified':True,
                  'member_count':len(manifest),'zip_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),
                  'evidence_boundary':'WHITELIST_REPORTS_AND_SYNTHETIC_SCREENS_NOT_PHONE_E2E'}
    out.with_suffix('.verification.json').write_text(json.dumps(verified,indent=2),encoding='utf-8')
    print('RESULT_ZIP='+str(out));print('ZIP_SHA256='+hashlib.sha256(out.read_bytes()).hexdigest())


if __name__=='__main__':main()
