"""HOST fake generated TLS setup/lifecycle checks; no ADB, TLS or fd mutation."""
import ast
import builtins
import copy
import hashlib
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'host'))
import device_tls

AREA='/mnt/data/p011-toolbox'
NAMES=('SOURCE.sha256',)+tuple('runtime/'+name for name in sorted(device_tls.SOURCE_NAMES))


def metadata(mode,inode,size=0):
    return types.SimpleNamespace(st_dev=11,st_ino=inode,st_mode=mode,st_uid=0,st_gid=0,
        st_nlink=1,st_size=size,st_mtime_ns=100,st_ctime_ns=200)


class FakePath:
    def __init__(self):self.redirects={}
    @staticmethod
    def isabs(value):return value.startswith('/')
    def realpath(self,value):return self.redirects.get(value,value)
    @staticmethod
    def isdir(value):return True


class FakeOS:
    """Only synthetic descriptor IDs; methods never call the actual OS."""
    O_RDONLY=0;O_NOFOLLOW=0x20000;O_NONBLOCK=0x800

    def __init__(self,target,data):
        self.target=target;self.path=FakePath();self.rows={};self.data={};self.fds={}
        self.offsets={};self.opened=[];self.closed=[];self.writes=[];self.verified=set()
        self.close_fail=set();self.write_fail=None;self.before_write=None;self.readback_hook=None
        for index,path in enumerate((AREA,AREA+'/candidates',target,target+'/runtime')):
            self.rows[path]=metadata(stat.S_IFDIR|0o700,20+index)
        for index,name in enumerate(NAMES):
            path=target+'/'+name;self.rows[path]=metadata(stat.S_IFREG|0o666,100+index,len(data[name]))
            self.data[path]=data[name]

    @staticmethod
    def geteuid():return 0
    def listdir(self,path):
        if path==self.target:return ['SOURCE.sha256','runtime']
        if path==self.target+'/runtime':return [name[8:] for name in NAMES[1:]]
        raise AssertionError('HOST unexpected directory')
    def lstat(self,path):
        if self.before_write and len(self.verified)==8 and not self.writes:
            hook=self.before_write;self.before_write=None;hook(self)
        return copy.copy(self.rows[path])
    def fstat(self,fd):return copy.copy(self.rows[self.fds[fd]])
    def open(self,path,flags):
        if flags!=(self.O_RDONLY|self.O_NOFOLLOW|self.O_NONBLOCK):raise AssertionError('HOST unsafe open')
        if path not in self.data:raise AssertionError('HOST arbitrary file')
        fd=200+len(self.opened);self.fds[fd]=path;self.offsets[fd]=0;self.opened.append((fd,path));return fd
    def lseek(self,fd,offset,whence):
        if (offset,whence)!=(0,0):raise AssertionError('HOST unexpected seek')
        self.offsets[fd]=0
    def read(self,fd,count):
        path=self.fds[fd];offset=self.offsets[fd];value=self.data[path][offset:offset+count]
        self.offsets[fd]+=len(value)
        if not value:self.verified.add(fd)
        return value
    def fchmod(self,fd,mode):
        if set(self.verified)!=set(self.fds) or len(self.fds)!=8:raise AssertionError('HOST write before all pins')
        if mode!=0o400:raise AssertionError('HOST other permission')
        if self.write_fail==fd:raise OSError('HOST injected write failure')
        self.writes.append((fd,mode));row=self.rows[self.fds[fd]];row.st_mode=stat.S_IFREG|mode;row.st_ctime_ns+=1
        if self.readback_hook:self.readback_hook(self,fd)
    def close(self,fd):
        self.closed.append(fd)
        if fd in self.close_fail:raise OSError('HOST injected close failure')


class FakeClock:
    @staticmethod
    def monotonic():return 1.0


class PermissionsTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix='mta-host-tls-setup-')
        self.staging=Path(self.directory.name);(self.staging/'runtime').mkdir()
        self.data={name:('HOST fixture '+name+'\n').encode('ascii') for name in NAMES}
        for name,value in self.data.items():(self.staging/name).write_bytes(value)
        self.identity=hashlib.sha256(self.data['SOURCE.sha256']).hexdigest()[:16]
        self.target=AREA+'/candidates/mta-01-'+self.identity
        self.script=device_tls.permissions_source(self.target,self.staging)
        self.fake=FakeOS(self.target,self.data)

    def tearDown(self):self.directory.cleanup()

    def execute(self):
        original=builtins.__import__
        fake_sys=types.SimpleNamespace(flags=types.SimpleNamespace(optimize=0))
        def importing(name,*args,**kwargs):
            if name=='os':return self.fake
            if name=='time':return FakeClock
            if name=='sys':return fake_sys
            return original(name,*args,**kwargs)
        scope={'__builtins__':dict(vars(builtins),__import__=importing)}
        output=io.StringIO()
        with redirect_stdout(output):exec(compile(self.script,'HOST-private-permissions','exec'),scope)
        text=output.getvalue().strip()
        self.assertTrue(text.startswith('RESULT='));return ast.literal_eval(text[7:])

    def rejected(self,exception=ValueError):
        with self.assertRaises(exception):self.execute()
        self.assertEqual(set(self.fake.closed),set(self.fake.fds))

    def test_generated_setup_and_body_are_python35_ast(self):
        ast.parse(self.script,feature_version=(3,5))
        body=device_tls.source(self.target,AREA+'/sessions/mta-tls-HOST',self.identity)
        ast.parse(body,feature_version=(3,5))

    def test_exact_seven_dependencies_plus_manifest_and_no_arbitrary_path(self):
        self.assertEqual(device_tls.SOURCE_NAMES,('p011_json.py','mta_safety.py','mta_protocol.py',
            'mta_files.py','mta_storage.py','mta_transport.py','mta_sender.py'))
        self.assertEqual(len(NAMES),8)
        tree=ast.parse(self.script)
        expected=next(ast.literal_eval(row.value) for row in tree.body if isinstance(row,ast.Assign)
            and any(isinstance(name,ast.Name) and name.id=='EXPECTED' for name in row.targets))
        self.assertEqual(tuple(row[0] for row in expected),NAMES)
        self.assertFalse(any('../' in row[0] or row[0].startswith('/') for row in expected))
        calls=[row.func.attr for row in ast.walk(tree) if isinstance(row,ast.Call) and isinstance(row.func,ast.Attribute)
            and isinstance(row.func.value,ast.Name) and row.func.value.id=='os']
        self.assertNotIn('chmod',calls);self.assertNotIn('unlink',calls);self.assertNotIn('rmdir',calls)
        for bad in ('/etc/mta-HOST',AREA+'/candidates/mta-01-deadbeefdeadbeef',self.target+'/../other'):
            with self.assertRaises(ValueError):device_tls.permissions_source(bad,self.staging)

    def test_all_eight_pins_before_first_permission_write_and_all_close(self):
        result=self.execute()
        self.assertEqual(result,{'complete':True,'file_count':8,'permission_writes':8,'descriptors_closed':True})
        self.assertEqual(len(self.fake.writes),8);self.assertEqual(len(self.fake.closed),8)
        self.assertEqual({path for _,path in self.fake.opened},{self.target+'/'+name for name in NAMES})

    def test_generated_candidate_binding_rejects_tampered_target_before_open(self):
        self.script=self.script.replace('TARGET='+repr(self.target),'TARGET='+repr(AREA+'/candidates/mta-01-HOST-foreign'),1)
        self.rejected();self.assertEqual(self.fake.opened,[])

    def test_existing_0400_files_are_verified_without_writes(self):
        for name in NAMES:self.fake.rows[self.target+'/'+name].st_mode=stat.S_IFREG|0o400
        result=self.execute();self.assertEqual(result['permission_writes'],0);self.assertEqual(len(self.fake.closed),8)

    def test_final_file_wrong_hash_no_file_has_been_modified(self):
        path=self.target+'/'+NAMES[-1];self.fake.data[path]=b'X'*len(self.fake.data[path])
        self.rejected();self.assertEqual(self.fake.writes,[]);self.assertEqual(len(self.fake.closed),8)

    def test_bad_owner_link_count_type_size_permissions_or_unknown_metadata_fail_closed(self):
        for field,value in (('st_uid',1),('st_uid',None),('st_nlink',2),('st_mode',stat.S_IFLNK|0o666),
                ('st_size',1),('st_mode',stat.S_IFREG|0o644)):
            with self.subTest(field=field,value=value):
                self.fake=FakeOS(self.target,self.data);setattr(self.fake.rows[self.target+'/'+NAMES[-1]],field,value)
                self.rejected();self.assertEqual(self.fake.writes,[])
        self.fake=FakeOS(self.target,self.data);del self.fake.rows[self.target+'/'+NAMES[-1]].st_ctime_ns
        self.rejected(AttributeError);self.assertEqual(self.fake.writes,[])

    def test_path_fd_inode_swap_fails_before_permissions(self):
        original=self.fake.fstat
        def mismatch(fd):
            value=original(fd)
            if self.fake.fds[fd]==self.target+'/'+NAMES[-1]:value.st_ino+=1000
            return value
        self.fake.fstat=mismatch;self.rejected();self.assertEqual(self.fake.writes,[])

    def test_after_all_pins_before_first_write_metadata_swap_is_rejected(self):
        self.fake.before_write=lambda value:setattr(value.rows[self.target+'/'+NAMES[0]],'st_ino',5555)
        self.rejected();self.assertEqual(self.fake.writes,[])

    def test_redirected_private_directory_or_extra_member_is_rejected_without_open(self):
        self.fake.path.redirects[self.target]='/foreign'
        self.rejected();self.assertEqual(self.fake.opened,[])
        self.fake=FakeOS(self.target,self.data);original=self.fake.listdir
        self.fake.listdir=lambda path:original(path)+(['extra'] if path==self.target else [])
        self.rejected();self.assertEqual(self.fake.opened,[])

    def test_partial_fchmod_failure_preserves_failure_and_attempts_all_fd_closes(self):
        self.fake.write_fail=201;self.rejected(OSError)
        self.assertEqual(self.fake.writes,[(200,0o400)]);self.assertEqual(len(self.fake.closed),8)

    def test_partial_open_failure_closes_all_previously_opened_without_write(self):
        original=self.fake.open
        def fail_last(path,flags):
            if path==self.target+'/'+NAMES[-1]:raise OSError('HOST injected open failure')
            return original(path,flags)
        self.fake.open=fail_last;self.rejected(OSError)
        self.assertEqual(len(self.fake.closed),7);self.assertEqual(self.fake.writes,[])

    def test_unknown_directory_owner_is_rejected_before_any_file(self):
        self.fake.rows[self.target].st_uid=None
        self.rejected();self.assertEqual(self.fake.opened,[])

    def test_readback_hash_or_metadata_failure_cannot_print_complete(self):
        def corrupt(fake,fd):fake.data[fake.fds[fd]]=b'X'*len(fake.data[fake.fds[fd]])
        self.fake.readback_hook=corrupt;self.rejected();self.assertEqual(len(self.fake.writes),1)
        self.fake=FakeOS(self.target,self.data)
        self.fake.readback_hook=lambda fake,fd:setattr(fake.rows[fake.fds[fd]],'st_uid',1)
        self.rejected();self.assertEqual(len(self.fake.writes),1)

    def test_one_fd_close_error_still_attempts_every_descriptor(self):
        self.fake.close_fail={200,204};self.rejected()
        self.assertEqual(self.fake.closed,list(range(200,208)))


class FakeRaw:
    @staticmethod
    def fileno():return -1


class FakeOwner:
    def __init__(self,resources):
        self.resources=resources;self.proof={'recognized_raw':True,'all_sockets_closed':True,
            'all_actors_exited':True,'close_verified':True,'cleanup_pending':False}
        self._workers=[];self._listener_thread=None;self._listener=resources[0]
        self.close_result=True;self.closed_result=True;self.requested=[]
    def close(self,timeout):self.requested.append(timeout);return self.close_result
    def closed(self):return self.closed_result
    def lifecycle_status(self):return {'closing':True,'socket_records':len(self.resources),'sockets_pending':0,
        'actors_pending':0,'threads_pending':0,'wrappers_pending':0,'unknown_wrappers':0,'unknown_resources':0,
        'processes_pending':0,'close_verified':True,'cleanup_pending':False,'PRIVATE':'not public'}
    def closure_snapshot(self,raw):
        value=dict(self.proof)
        if not any(item is raw for item in self.resources):value['recognized_raw']=False
        return value


class ClosureTests(unittest.TestCase):
    def setUp(self):
        tree=ast.parse(device_tls.DEVICE_BODY)
        outer=next(row for row in tree.body if isinstance(row,ast.Try))
        self.finally_source=ast.fix_missing_locations(ast.Module(body=outer.finalbody,type_ignores=[]))
        self.receiver=FakeOwner([FakeRaw(),FakeRaw()]);self.sender=FakeOwner([FakeRaw()])

    def execute(self,replace_scoped=False):
        result={'pass':True,'receiver_transport_closed':False,'sender_transport_closed':False,
            'receiver_closure_proofs_verified':False,'sender_closure_proof_verified':False}
        scoped=[(raw,'127.0.0.1',('127.0.0.1',1234)) for raw in self.receiver.resources]
        if replace_scoped:scoped[0]=(FakeRaw(),'127.0.0.1',('127.0.0.1',1234))
        scope={'result':result,'patch_active':False,'process':None,'receiver':self.receiver,'server':self.sender,
            'scoped':scoped,'listeners':[(self.sender.resources[0],('127.0.0.1',1234))],
            'selection':types.SimpleNamespace(close=lambda:None,closed=True),'SESSION':AREA+'/sessions/mta-tls-HOST',
            'os':types.SimpleNamespace(path=FakePath(),listdir=lambda path:[]),'time':FakeClock,'started':1.0}
        exec(compile(self.finally_source,'HOST-private-TLS-finally','exec'),scope)
        return result

    def test_script_pass_requires_both_exact_resource_proofs_and_actual_closed(self):
        value=self.execute();self.assertTrue(value['pass']);self.assertTrue(value['owned_cleanup_verified'])
        self.assertEqual(self.receiver.requested,[2]);self.assertEqual(self.sender.requested,[2])

    def test_every_closure_flag_missing_false_or_truthy_non_bool_blocks_pass(self):
        for owner_name in ('receiver','sender'):
            for field in ('recognized_raw','all_sockets_closed','all_actors_exited','close_verified','cleanup_pending'):
                for invalid in (None,False if field!='cleanup_pending' else True,1,'yes'):
                    with self.subTest(owner=owner_name,field=field,value=invalid):
                        self.receiver=FakeOwner([FakeRaw(),FakeRaw()]);self.sender=FakeOwner([FakeRaw()])
                        getattr(self,owner_name).proof[field]=invalid
                        self.assertFalse(self.execute()['pass'])
                self.receiver=FakeOwner([FakeRaw(),FakeRaw()]);self.sender=FakeOwner([FakeRaw()])
                getattr(self,owner_name).proof.pop(field)
                self.assertFalse(self.execute()['pass'])

    def test_foreign_raw_fd_minus_one_cannot_match_exact_closure_resource(self):
        value=self.execute(replace_scoped=True)
        self.assertFalse(value['pass']);self.assertFalse(value['receiver_closure_proofs_verified'])

    def test_close_request_or_still_alive_thread_is_not_pass(self):
        self.receiver.close_result=False;self.assertFalse(self.execute()['pass'])
        self.receiver.close_result=True;self.sender.closed_result=False;self.assertFalse(self.execute()['pass'])
        self.sender.closed_result=True;self.sender._workers=[types.SimpleNamespace(is_alive=lambda:True)]
        self.assertFalse(self.execute()['pass'])

    def test_public_lifecycle_has_only_fixed_counts_including_unknown_resources(self):
        result=self.execute()
        for name in ('receiver_lifecycle','sender_lifecycle'):
            self.assertNotIn('PRIVATE',result[name]);self.assertIn('unknown_resources',result[name])
            self.assertTrue(set(result[name]).issubset({'closing','socket_records','sockets_pending','actors_pending',
                'threads_pending','wrappers_pending','unknown_wrappers','unknown_resources','processes_pending',
                'close_verified','cleanup_pending'}))


if __name__=='__main__':unittest.main()
