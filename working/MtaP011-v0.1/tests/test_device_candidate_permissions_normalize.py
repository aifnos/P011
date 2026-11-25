"""Specialized HOST simulation only: no ADB or actual chmod/chown/ZIP."""
import ast
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

PROJECT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT/'host'));sys.path.insert(0,str(PROJECT/'runtime'))
import device_candidate_permissions_normalize as tool
from tests import test_device_prior_journal_readonly as remote_fixture
from tests import test_device_p2p_v6diag as baseline_fixture


def body_fixture(action='first'):
    known=copy.deepcopy(tool.CANDIDATES);data={};modes={};ctime={};inodes={};paths=[];walks=[]
    for alias,value in known.items():
        base='/mnt/data/p011-toolbox/candidates/mta-01-'+value['identity']
        for relative in sorted(value['pins']):
            path=base+'/'+relative;raw=('HOST_PRIVATE_'+alias+relative).encode('ascii');paths.append(path)
            data[path]=raw;value['sizes'][relative]=len(raw);value['pins'][relative]=hashlib.sha256(raw).hexdigest()
            modes[path]=(0o500 if relative.startswith('native/') else 0o400) if action=='idempotent' else (0o700 if relative.startswith('native/') else 0o666)
            ctime[path]=1;inodes[path]=len(paths)
        walks.extend([(base,['native','runtime'],['SOURCE.sha256']),
            (base+'/native',[],sorted(name.split('/')[1] for name in value['pins'] if name.startswith('native/'))),
            (base+'/runtime',[],sorted(name.split('/')[1] for name in value['pins'] if name.startswith('runtime/')))])
    first=paths[0];last=paths[-1];opened=[];closed=[];fchmod=[];fd_path={};position={};fstat_count={};os_calls=[]
    if action=='hash':data[last]=b'X'+data[last][1:]
    if action=='short':data[last]=data[last][:-1]
    if action=='unknown_mode':modes[last]=0o644
    if action=='unknown_special':modes[last]|=0o4000
    def metadata(path):
        kind=stat.S_IFLNK if action=='link' and path==last else stat.S_IFREG
        value=types.SimpleNamespace(st_dev=1,st_ino=inodes[path],st_mode=kind|modes[path],st_uid=1 if action=='foreign' and path==last else 0,
            st_gid=0,st_nlink=2 if action=='nlink' and path==last else 1,st_size=len(data[path]),st_mtime_ns=1,st_ctime_ns=ctime[path])
        return value
    def open_file(path,flags):
        if flags!=0x20000:raise AssertionError('Expected RDONLY|NOFOLLOW')
        fd=len(opened)+10;opened.append(path);fd_path[fd]=path;position[fd]=0;os_calls.append(('open',path));return fd
    def fstat_file(fd):
        path=fd_path[fd];fstat_count[fd]=fstat_count.get(fd,0)+1
        if action=='unknown_after_failure' and len(fchmod)>=3 and path==fd_path[12]:raise OSError(5,'HOST_SECRET')
        value=metadata(path)
        if action=='identity_before' and len(opened)==16 and not fchmod and path==first:value.st_ino+=1
        if action=='identity_after' and fchmod and path==first:value.st_nlink=2
        return value
    def read_file(fd,count):
        if not 1<=count<=65536:raise AssertionError('Unbounded read')
        path=fd_path[fd];start=position[fd];chunk=data[path][start:start+count];position[fd]+=len(chunk);return chunk
    def seek_file(fd,offset,whence):
        if offset!=0 or whence!=0:raise AssertionError('Unexpected seek')
        position[fd]=0
    def fchmod_file(fd,mode):
        if len(opened)!=16 or namespace['result']['prevalidated_count']!=16 or not namespace['result']['all_prevalidated_before_writes']:
            raise AssertionError('Write before all descriptors validated')
        fchmod.append((fd,mode));os_calls.append(('fchmod',fd))
        if len(fchmod)==3 and action in ('fchmod_failure','unknown_after_failure'):raise OSError(5,'HOST_SECRET')
        path=fd_path[fd];modes[path]=mode;ctime[path]+=1
        if len(fchmod)==3 and action=='fchmod_applied_then_failure':raise OSError(5,'HOST_SECRET')
    def close_file(fd):
        closed.append(fd)
        if action=='close_failure' and fd==10:raise OSError(5,'HOST_SECRET')
    clock=[]
    def monotonic():
        clock.append(True)
        if action=='deadline' and len(clock)>1:return 60
        if action=='deadline_partial' and len(fchmod)>=2:return 60
        return 1
    def walk(base,followlinks=False):
        if followlinks:raise AssertionError('Followed links')
        rows=[copy.deepcopy(row) for row in walks if row[0]==base or row[0].startswith(base+'/')]
        if action=='extra' and base in first:rows[0][2].append('HOST_PRIVATE_EXTRA')
        return rows
    os_mock=types.SimpleNamespace(lstat=metadata,fstat=fstat_file,open=open_file,read=read_file,lseek=seek_file,fchmod=fchmod_file,close=close_file,
        set_inheritable=lambda fd,value:None,geteuid=lambda:0,O_RDONLY=0,O_NOFOLLOW=0x20000,SEEK_SET=0,walk=walk,sep='/',
        path=types.SimpleNamespace(islink=lambda unused:False,relpath=lambda path,base:path[len(base)+1:]))
    namespace={'CANDIDATES':known,'AREA':'/mnt/data/p011-toolbox','VALUE_REASONS':tuple(tool.REASONS),
        'hashlib':hashlib,'stat':stat,'os':os_mock,'time':types.SimpleNamespace(monotonic=monotonic),
        'private_folder':lambda unused:None,'owned_directory':lambda unused:None}
    buffer=io.StringIO()
    with contextlib.redirect_stdout(buffer):exec(tool.BODY,namespace)
    value=ast.literal_eval(buffer.getvalue().split('RESULT=',1)[1].strip());tool.validate_result(value)
    return value,opened,closed,fchmod,os_calls


class FixedNormalizationTests(unittest.TestCase):
    def test_reference_and_35_program_only_fd_fchmod_not_path_or_other_write(self):
        with mock.patch.object(tool,'Adb',side_effect=AssertionError('No ADB')):
            safety=tool.verify_reference();program=tool.source(safety)
        tree=ast.parse(program,feature_version=(3,5));self.assertFalse(any(isinstance(node,ast.Assert) for node in ast.walk(tree)))
        body=ast.parse(tool.BODY,feature_version=(3,5))
        names=[node.func.attr for node in ast.walk(body) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)]
        self.assertEqual(names.count('fchmod'),1)
        for forbidden in ('chmod','chown','unlink','remove','mkdir','recover','restore','start','stop','bind','connect','sendto'):self.assertNotIn(forbidden,names)
        self.assertIn('end=time.monotonic()+25',tool.BODY)

    def test_first_all_descriptors_validate_before_write_complete_readback(self):
        value,opened,closed,writes,calls=body_fixture()
        self.assertTrue(value['complete']);self.assertTrue(value['all_prevalidated_before_writes']);self.assertTrue(value['descriptors_all_closed'])
        self.assertEqual((value['prevalidated_count'],value['partial_change_count'],value['readback_count'],value['fchmod_attempt_count']),(16,16,16,16))
        self.assertEqual(len(closed),16);self.assertEqual([name for name,arg in calls[:16]],['open']*16)
        for row in value['files']:self.assertEqual(row['new_mode'],0o500 if row['relative'].startswith('native/') else 0o400)
        self.assertNotIn('HOST_PRIVATE',json.dumps(value));self.assertNotIn('HOST_SECRET',json.dumps(value));self.assertNotIn('/mnt/',json.dumps(value))

    def test_idempotent_no_repeated_write_and_complete_descriptor_readbacks(self):
        value,opened,closed,writes,calls=body_fixture('idempotent')
        self.assertTrue(value['complete']);self.assertEqual(writes,[])
        self.assertEqual((value['fchmod_attempt_count'],value['partial_change_count'],value['readback_count']),(0,0,16))
        self.assertEqual(len(closed),16)

    def test_foreign_link_nlink_bad_hash_extra_or_unknown_mode_before_any_write(self):
        reasons={'foreign':'foreign_owner','link':'file_not_regular','nlink':'file_link_count','hash':'file_pin_mismatch',
                 'short':'file_pin_mismatch','extra':'candidate_contents_invalid','unknown_mode':'unknown_file_mode','unknown_special':'unknown_file_mode'}
        for action,reason in reasons.items():
            value,opened,closed,writes,calls=body_fixture(action)
            self.assertFalse(value['complete']);self.assertFalse(value['all_prevalidated_before_writes']);self.assertEqual(writes,[])
            self.assertEqual(value['reason'],reason);self.assertEqual(len(closed),len(opened));self.assertEqual(value['partial_change_count'],0)

    def test_fchmod_failure_reports_partial_no_rollback_and_all_close(self):
        for action,expected in (('fchmod_failure',2),('fchmod_applied_then_failure',3)):
            value,opened,closed,writes,calls=body_fixture(action)
            self.assertFalse(value['complete']);self.assertEqual(value['first_failure_stage'],'fchmod');self.assertEqual(value['errno'],5)
            self.assertEqual((value['fchmod_attempt_count'],value['partial_change_count'],value['readback_count']),(3,expected,2))
            self.assertTrue(value['change_count_complete']);self.assertEqual(len(closed),16);self.assertEqual(len(writes),3)

    def test_failed_call_unreadable_state_is_unknown_not_no_change(self):
        value,opened,closed,writes,calls=body_fixture('unknown_after_failure')
        self.assertFalse(value['change_count_complete']);self.assertFalse(value['files'][2]['mode_observed'])
        self.assertFalse(value['complete']);self.assertEqual(len(closed),16)

    def test_identity_change_before_or_after_fchmod_fails_exactly(self):
        for action,expected_writes in (('identity_before',0),('identity_after',1)):
            value,opened,closed,writes,calls=body_fixture(action)
            self.assertFalse(value['complete']);self.assertEqual(value['reason'],'file_identity_changed');self.assertEqual(len(writes),expected_writes)
            self.assertEqual(len(closed),16)

    def test_deadline_before_or_after_writes_closes_every_fd_truthfully(self):
        value,opened,closed,writes,calls=body_fixture('deadline')
        self.assertEqual(value['reason'],'readonly_permission_deadline');self.assertEqual(opened,[]);self.assertEqual(writes,[])
        value,opened,closed,writes,calls=body_fixture('deadline_partial')
        self.assertFalse(value['complete']);self.assertEqual(value['partial_change_count'],2);self.assertEqual(value['readback_count'],1)
        self.assertEqual(value['first_failure_stage'],'readback');self.assertEqual(len(closed),16)

    def test_close_failure_does_not_skip_remaining_fifteen(self):
        value,opened,closed,writes,calls=body_fixture('close_failure')
        self.assertFalse(value['complete']);self.assertFalse(value['descriptors_all_closed'])
        self.assertEqual((value['fd_close_attempt_count'],value['fd_closed_count'],value['fd_close_failed_count']),(16,15,1))
        self.assertEqual(value['first_failure_stage'],'close');self.assertEqual(len(closed),16)

    def test_strict_public_counts_modes_bools_and_partial_evidence(self):
        valid=body_fixture()[0];variants=[]
        for field,value in (('partial_change_count',0),('file_count',True),('fd_closed_count',15),('reason','HOST_SECRET')):
            row=copy.deepcopy(valid);row[field]=value;variants.append(row)
        for field,value in (('new_mode',True),('new_mode',512),('old_mode',0o644),('relative','/HOST_SECRET'),('hash_unchanged',1),('changed',False)):
            row=copy.deepcopy(valid);row['files'][0][field]=value;variants.append(row)
        row=copy.deepcopy(valid);row['files'][0]['uid']=0;variants.append(row)
        row=copy.deepcopy(valid);row['all_prevalidated_before_writes']=False;variants.append(row)
        for value in variants:
            with self.assertRaises(ValueError):tool.validate_result(value)


class FakeAdb(remote_fixture.FakeAdb):
    def run(self,label,arguments,timeout=None,input_data=None):
        self.index+=1;self.calls.append((label,arguments,timeout,input_data));ast.parse(input_data.decode('utf-8'),feature_version=(3,5))
        if label=='fixed-permission-normalize-reviewed':value=body_fixture('fchmod_failure' if self.action=='partial' else 'first')[0]
        else:
            value=baseline_fixture.private_probe()
            if label=='after-normalize-reviewed' and self.action=='original_changed':value['network_processes']=[]
        return remote_fixture.wire(value)


class HostDispatchTests(unittest.TestCase):
    def invoke(self,directory,action):
        actors=[]
        def factory(path):
            actor=FakeAdb(path,action);actors.append(actor);return actor
        with mock.patch.object(tool,'Adb',side_effect=factory),mock.patch.object(tool,'save_public',side_effect=lambda report,out:out/'HOST_NO_ACTUAL_ZIP'):
            report,out,archive=tool.run_normalize(Path(directory)/'HOST_ONLY_OUTPUT')
        self.assertFalse(archive.exists())
        return report,actors[0]

    def test_original_changed_or_partial_failure_stops_no_rf_retry_or_recovery(self):
        for action in ('partial','original_changed'):
            with tempfile.TemporaryDirectory() as directory:
                report,actor=self.invoke(directory,action)
                self.assertFalse(report['normalization_complete']);self.assertTrue(report['permission_write_requested'])
                self.assertEqual([row[0] for row in actor.calls],['before-normalize-reviewed','fixed-permission-normalize-reviewed','after-normalize-reviewed'])
                for field in ('radio_operations','network_configuration','candidate_staged','chown_requested','rollback_invoked','recovery_invoked','retry_invoked','send_available'):
                    self.assertFalse(report[field])
                if action=='partial':self.assertEqual(report['normalization']['partial_change_count'],2)

    def test_fixed_explicit_mode_only_and_changed_reference_before_adb(self):
        for argv in (['program'],['program','--check-readonly'],['program','--normalize-reviewed','--candidate','HOST_SECRET'],['program','--normalize-reviewed','--chmod','777']):
            with mock.patch.object(sys,'argv',argv),mock.patch.object(tool,'Adb',side_effect=AssertionError('No ADB')),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):tool.main()
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'UNCREATED'
            with mock.patch.object(tool,'PERMISSIONS_CHECKER_SHA256','0'*64),mock.patch.object(tool,'Adb',side_effect=AssertionError('No ADB')),self.assertRaises(ValueError):tool.run_normalize(output)
            self.assertFalse(output.exists())


if __name__=='__main__':unittest.main()
