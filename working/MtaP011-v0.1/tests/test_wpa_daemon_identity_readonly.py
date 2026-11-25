"""Only Fake filesystem/reader and source reads; no actual target/OS actions."""
import ast
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

PATH = Path(__file__).absolute().parents[1]/'host/wpa_daemon_identity_readonly.py'
spec = importlib.util.spec_from_file_location('wpa_readonly_check',str(PATH))
check = importlib.util.module_from_spec(spec);spec.loader.exec_module(check)
HEADER = b'Num       RefCount Protocol Flags    Type St Inode Path\n'


def unix(inode=555, kind=2, path=b'/run/wpa_supplicant/wlan0'):
    return HEADER+b'00000000: 00000002 00000000 00000000 %04X 01 %d '%(kind,inode)+path+b'\n'


class FakeFs(object):
    O_RDONLY,O_CLOEXEC,O_NONBLOCK,O_NOFOLLOW=0,0x80000,0x800,0x20000
    def __init__(self):
        self.argv=b'/usr/sbin/wpa_supplicant\0-iwlan0\0-c/PRIVATE_CONFIG\0'
        self.data={'/proc/41/comm':b'wpa_supplicant\n','/proc/42/comm':b'other\n',
            '/proc/41/cmdline':self.argv,'/proc/41/status':b'Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n',
            '/proc/41/exe':b'\x7fELFHOST_ONLY','/proc/net/unix':unix()}
        self.dirs={'/proc':['41','42','net'],'/proc/41/fd':['3','4'],'/sys/class/net':['lo','wlan0']}
        self.links={'/proc/41/exe':'/usr/sbin/wpa_supplicant','/proc/41/fd/3':'socket:[555]','/proc/41/fd/4':'socket:[999]'}
        for name in ('mnt','net','pid','user'):
            self.links['/proc/41/ns/'+name]=name+':[123]';self.links['/proc/self/ns/'+name]=name+':[123]'
        self.live={};self.closed=[];self.opened=[];self.nextfd=100;self.clock_value=0.0
        self.close_error=False;self.hidden_open=False;self.foreign_fd=False;self.path_change=False
        self.private_mode=stat.S_IFDIR|0o755;self.euid=0;self.names_count=0
    def clock(self):return self.clock_value
    def geteuid(self):return self.euid
    def uname(self):return ('Linux','','','','armv7l')
    def listdir(self,path):return list(self.dirs[path])
    def readlink(self,path):return self.links[path]
    def metadata(self,path):
        inode=123 if path=='/proc/41/exe' else 900+list(self.data).index(path)
        return SimpleNamespace(st_dev=1,st_ino=inode,st_mode=stat.S_IFREG|(0o755 if path.endswith('/exe') else 0o444),
            st_uid=0,st_gid=0,st_nlink=1,st_size=len(self.data[path]),st_mtime_ns=1,st_ctime_ns=1)
    def open(self,path,flags):
        if path not in self.data:raise OSError(errno.ENOENT,'private missing')
        if flags&3:raise AssertionError('write open forbidden')
        fd=self.nextfd;self.nextfd+=1;self.opened.append((path,flags));self.live[fd]=[path,0]
        if self.hidden_open:raise RuntimeError('PRIVATE_HIDDEN_FD')
        if self.foreign_fd:return True
        return fd
    def fstat(self,fd):
        if fd not in self.live:raise OSError(errno.EBADF,'private closed')
        return self.metadata(self.live[fd][0])
    def read(self,fd,size):
        path,at=self.live[fd];data=self.data[path][at:at+size];self.live[fd][1]+=len(data);return data
    def close(self,fd):
        self.closed.append(fd)
        if self.close_error:raise OSError(errno.EIO,'PRIVATE_CLOSE_ERROR')
        del self.live[fd]
    def lstat(self,path):
        self.names_count+=1
        return SimpleNamespace(st_dev=2,st_ino=777+(1 if self.path_change and self.names_count>4 else 0),
            st_mode=stat.S_IFSOCK|0o660 if path.endswith('/wlan0') else self.private_mode,
            st_uid=0,st_gid=0,st_nlink=1,st_size=0,st_mtime_ns=1,st_ctime_ns=1)


class Reader(object):
    def __init__(self,modules,fs):self.modules,self.fs,self.calls,self.pending,self.changed=modules,fs,[],False,False
    def read_actor(self,pid,expected=None):
        self.calls.append((pid,expected));start=11+int(self.changed and len(self.calls)>1)
        actor=self.modules['mta_p2p_client_init'].Actor(pid,start,'/usr/sbin/wpa_supplicant',hashlib.sha256(self.fs.argv).hexdigest(),((pid,start,'S'),))
        raw=(self.modules['mta_client_proc'].RawRecord('HOST_FAKE',1,'PRIVATE_RAW',b'PRIVATE_ACTOR',()),)
        return self.modules['mta_client_proc'].ProcObservation('live_actor','', 'HOST_FAKE','11111111-1111-1111-1111-111111111111',actor,False,(),True,2,raw,12,12,self.pending,1)


class MemoryPath(object):
    def __init__(self,store,name):self.store,self.name=store,name
    def __truediv__(self,name):return MemoryPath(self.store,self.name+'/'+name)
    def __str__(self):return self.name
    def with_suffix(self,suffix):return MemoryPath(self.store,self.name+suffix)
    def mkdir(self,parents=False,exist_ok=False):
        if self.name in self.store['dirs'] and not exist_ok:raise FileExistsError(errno.EEXIST,'PRIVATE_OUTPUT')
        self.store['dirs'].append(self.name)
    def exists(self):return self.name in self.store['files']
    def open(self,mode):
        if mode!='rb':raise AssertionError('only Fake captured raw read')
        return io.BytesIO(self.store['files'][self.name])
    def write_text(self,value,encoding):
        if self.store.get('exit_error') and self.name.endswith('.remote-exit'):raise OSError(errno.EIO,'PRIVATE_EXIT_OUTPUT')
        self.store['files'][self.name]=value.encode(encoding)


class MemoryZip(object):
    def __init__(self,store,path,mode,compression):
        if mode!='x':raise AssertionError('not immutable zip')
        self.store,self.path=store,str(path);store['bundles'][self.path]=[]
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def write(self,path,name):
        if not path.exists():raise AssertionError('missing companion')
        self.store['bundles'][self.path].append(name)


class Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks,cls.source=check.source_check();ns={}
        prefix=cls.source[:cls.source.index(check.REMOTE_CORE)]
        exec(prefix+check.REMOTE_CORE,ns);cls.ns=ns;cls.modules=ns['modules']
    def setUp(self):
        for name in ('open','mkdir','close','read','write','fsync','kill','fork','waitpid','execve'):
            if hasattr(os,name):
                p=mock.patch.object(os,name,side_effect=AssertionError('actual OS forbidden'));p.start();self.addCleanup(p.stop)
        for name in ('socket.socket','subprocess.run','ctypes.CDLL'):
            p=mock.patch(name,side_effect=AssertionError('actual external actions forbidden'));p.start();self.addCleanup(p.stop)
    def make(self):
        fs=FakeFs();reader=Reader(self.modules,fs)
        obj=self.ns['Collector'](self.modules['mta_client_proc'],self.modules['mta_p2p_client_init'],fs,fs.clock,reader)
        return obj,fs,reader
    def test_pure_ctor_and_pinned_source(self):
        obj,fs,reader=self.make();self.assertFalse(fs.opened);self.assertFalse(reader.calls);self.assertIsNone(obj.files)
        self.assertEqual(check.ADB_PIN,self.checks['adb_helper_sha256']);self.assertEqual(3,len(check.PINS))
    def test_default_cli_no_adb_and_exact_pin_requirement(self):
        with mock.patch.object(check,'run_readonly') as run,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0,check.main([]));self.assertEqual(0,check.main(['--source-check-only']));run.assert_not_called()
        for args in (['--execute-readonly'],['--expected-checker-sha256','a'*64],['--endpoint','/foreign']):
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):check.main(args)
        with mock.patch.object(check,'source_check',return_value=(self.checks,self.source)),self.assertRaises(ValueError):check.run_readonly('0'*64)
    def test_positive_real_component_types_and_distinct_socket_inode(self):
        obj,fs,reader=self.make();value=obj.collect();report=check._project(value)
        self.assertTrue(report['pass_value'],value['failure']);self.assertFalse(fs.live)
        self.assertEqual(2,len(reader.calls));self.assertIs(reader.calls[1][1],obj.private['actors'][0].actor)
        self.assertEqual(555,obj.private['endpoint_before']['row'][0]);self.assertEqual(777,obj.private['endpoint_before']['chain'][-1][1][1])
        self.assertEqual(report['file_count'],report['closed_count']);self.assertEqual(24,report['proc_closed_count'])
        with self.assertRaises(ValueError):obj.collect()
    def test_binary_has_full_hash_but_not_elf_copy_in_private_output(self):
        obj,fs,reader=self.make();value=obj.collect();image=obj.private['identity_before']
        self.assertEqual(hashlib.sha256(fs.data['/proc/41/exe']).hexdigest(),image['image_sha'])
        rows=[r for r in value['private']['reads'] if r[0].endswith('/exe')]
        self.assertEqual(2,len(rows));self.assertIs(type(rows[0][1]),dict);self.assertEqual(len(fs.data['/proc/41/exe']),rows[0][1]['bytes'])
    def test_public_never_has_identity_path_raw_or_daemon_sha(self):
        obj,fs,reader=self.make();value=obj.collect();public=json.dumps(check._project(value))
        for secret in ('PRIVATE',fs.argv.decode('utf-8'),'/run/','11111111',value['private']['identity_before']['image_sha']):self.assertNotIn(secret,public)
    def test_missing_wlan_preserves_other_facts_and_failure(self):
        obj,fs,reader=self.make();fs.dirs['/sys/class/net']=['lo'];value=obj.collect();public=check._project(value)
        self.assertFalse(public['pass_value']);self.assertEqual('wlan_absent',public['failure']['reason'])
        self.assertTrue(public['wlan_observed']);self.assertFalse(public['wlan_present'])
        self.assertTrue(public['endpoint_stable']);self.assertTrue(public['files_closed']);self.assertIn('identity_after',value['private'])
    def test_daemon_zero_multiple_or_invalid_numeric_fail_closed(self):
        for mode in ('none','multiple','pid'):
            obj,fs,reader=self.make()
            if mode=='none':fs.data['/proc/41/comm']=b'other\n'
            elif mode=='multiple':fs.data['/proc/42/comm']=b'wpa_supplicant\n'
            else:fs.dirs['/proc']=['9999999999']
            value=obj.collect();self.assertFalse(check._project(value)['pass_value']);self.assertFalse(reader.calls)
    def test_uid_namespace_and_actor_change_fail(self):
        for mode in ('uid','namespace','actor','pending'):
            obj,fs,reader=self.make()
            if mode=='uid':fs.data['/proc/41/status']=b'Uid: 1 1 1 1\nGid: 0 0 0 0\n'
            elif mode=='namespace':fs.links['/proc/41/ns/net']='net:[124]'
            elif mode=='actor':reader.changed=True
            else:reader.pending=True
            value=obj.collect();self.assertFalse(check._project(value)['pass_value'])
    def test_unknown_fd_or_close_keeps_refs_and_blocks_new_reads(self):
        for mode in ('hidden','malformed','close'):
            obj,fs,reader=self.make()
            if mode=='hidden':fs.hidden_open=True
            elif mode=='malformed':fs.foreign_fd=True
            else:fs.close_error=True
            value=obj.collect();self.assertTrue(value['summary']['resource_pending']);self.assertFalse(value['summary']['files_closed'])
            first=obj.files.refs[0];self.assertIs(first['fs'],fs);self.assertEqual(1,len(fs.opened));closed=tuple(fs.closed)
            with self.assertRaises(ValueError):obj.files.read('/proc/41/comm',64)
            obj.files.close(first);self.assertEqual(closed,tuple(fs.closed));self.assertTrue(fs.live)
    def test_foreign_endpoint_unlinked_abstract_stream_or_duplicate_rejected(self):
        for mode in ('foreign','unlinked','abstract','stream','duplicate'):
            obj,fs,reader=self.make()
            if mode=='foreign':fs.links['/proc/41/fd/3']='socket:[999]'
            elif mode=='unlinked':fs.data['/proc/net/unix']=HEADER
            elif mode=='abstract':fs.data['/proc/net/unix']=unix(path=b'@private-wlan0')
            elif mode=='stream':fs.data['/proc/net/unix']=unix(kind=1)
            else:fs.data['/proc/net/unix']=unix()+unix()[len(HEADER):]
            value=obj.collect();self.assertFalse(check._project(value)['pass_value'])
    def test_path_symlink_writable_or_changed_is_evidenced_not_repaired(self):
        for mode in ('symlink','writable','changed'):
            obj,fs,reader=self.make()
            if mode=='symlink':fs.private_mode=stat.S_IFLNK|0o777
            elif mode=='writable':fs.private_mode|=0o002
            else:fs.path_change=True
            value=obj.collect();self.assertFalse(check._project(value)['pass_value']);self.assertTrue(value['private']['path_observations'])
    def test_options_known_fields_no_config_read_or_duplicate(self):
        opts=self.ns['options'](b'/wpa\0-i\0wlan0\0-C/run/wpa\0-O/run/override\0-g/run/global\0-c/secret\0')
        self.assertEqual({'-i':'wlan0','-C':'/run/wpa','-O':'/run/override','-g':'/run/global'},opts)
        for bad in (b'/wpa\0-iwlan0\0-iwlan0\0',b'/wpa\0-i\0',b'/wpa\0-iwlan1\0',b'/wpa\0-iwlan0',b'/wpa\0\0'):
            with self.assertRaises(ValueError):self.ns['options'](bad)
    def test_unix_strict_header_hex_inode_line_and_size(self):
        for raw in (unix().replace(b'Type',b'Other'),unix().replace(b'0002',b'QQQQ'),unix().rstrip(b'\n'),unix().replace(b'555 ',b'-1 '),HEADER+b'x'*1048576):
            with self.assertRaises(ValueError):self.ns['unix_rows'](raw)
    def test_budget_platform_and_interrupt_first_failure_fixed(self):
        obj,fs,reader=self.make();fs.euid=1;value=obj.collect();self.assertEqual('platform',value['failure']['reason']);self.assertFalse(fs.opened)
        self.assertFalse(value['summary']['wlan_observed']);self.assertFalse(value['summary']['wlan_present'])
        obj,fs,reader=self.make();old=fs.listdir
        def interrupt(path):raise KeyboardInterrupt('PRIVATE_INTERRUPT')
        fs.listdir=interrupt;value=obj.collect();self.assertEqual('interrupted',value['failure']['reason']);self.assertIn('PRIVATE_INTERRUPT',value['private']['traceback'])
        obj,fs,reader=self.make();obj.collect();fs.clock_value=21
        with self.assertRaises(ValueError):obj.files.check()
    def test_project_rejects_false_success_bool_counts_and_free_failure(self):
        obj,fs,reader=self.make();good=obj.collect()
        for mode in ('count','bool','reason','closure','private','wlan'):
            value={'summary':dict(good['summary']),'failure':dict(good['failure']),'private':dict(good['private'])}
            if mode=='count':value['summary']['file_count']=True
            elif mode=='bool':value['summary']['daemon_stable']=1
            elif mode=='reason':value['failure']['reason']='PRIVATE_FREE_TEXT'
            elif mode=='closure':value['summary']['resource_pending']=True
            elif mode=='wlan':value['summary']['wlan_observed']=False
            else:value['private']['traceback']='x'*65537
            with self.assertRaises(ValueError):check._project(value)
    def test_strict_pty_exact_echo_and_no_unknown_output(self):
        value={'private':'PRIVATE'};tail=('RESULT='+repr(value)+'\nMTA_REMOTE_OK\n\nMTA_REMOTE_EXIT=0\n').encode()
        echo=b'fixed source\n';self.assertEqual(value,check._parse(echo.replace(b'\n',b'\r\r\n')+tail,echo))
        for raw in (b'extra\n'+tail,echo[:-1]+tail,echo.replace(b'fixed',b'other')+tail,tail+b'MTA_REMOTE_OK\n',tail.replace(b'EXIT=0',b'EXIT=1')):
            with self.assertRaises(ValueError):check._parse(raw,echo)
    def test_transport_and_python35_no_rf_socket_cli_or_file_mutation(self):
        command,data,echo=check._transport(self.source);self.assertEqual(data,echo);self.assertIsNotNone(data)
        self.assertIn('p011-wpa-daemon-facts',command);self.assertNotIn('wpa_cli',self.source)
        tree=ast.parse(self.source,feature_version=(3,5));ast.parse(PATH.read_text(encoding='utf-8'),feature_version=(3,5))
        attrs={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
        self.assertFalse({'write','mkdir','unlink','kill','socket','Popen','flock','chmod','chown'}&attrs)
        self.assertFalse(any(isinstance(n,ast.Assert) for n in ast.walk(tree)))
        host=ast.parse(PATH.read_text(encoding='utf-8'))
        self.assertFalse(any(isinstance(n,ast.Attribute) and n.attr in ('run_probe','PROBE','python') for n in ast.walk(host)))
    def host_fake(self,value,mode='good',exit_error=False):
        store={'files':{},'dirs':[],'bundles':{},'exit_error':exit_error};calls=[];owners=[]
        out=MemoryPath(store,'HOST_SYNTHETIC_OUTPUT');tail=('RESULT='+repr(value)+'\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n').encode()
        class FakeAdb(object):
            def __init__(self,directory):self.directory,self.index=directory,0
            def run(self,label,args,timeout,input_data):
                self.index+=1;calls.append((label,args,timeout,input_data))
                raw=(input_data or b'')+tail
                if mode=='free_output':raw=b'PRIVATE_EXTRA\n'+raw
                if mode=='host_exit':raw=b'MTA_REMOTE_EXIT=1\n'
                stem=self.directory/('%02d-original-wpa-identity'%self.index)
                store['files'][str(stem)+'.stdout.raw']=raw
                store['files'][str(stem)+'.stderr.raw']=b'PRIVATE_STDERR' if mode=='stderr' else b''
                store['files'][str(stem)+'.host-exit']=b'1' if mode=='host_exit' else b'0'
                if mode=='host_exit':raise RuntimeError('PRIVATE_HOST_EXIT')
                return raw
        def path(value):return value if type(value) is MemoryPath else MemoryPath(store,str(value))
        with mock.patch.object(check,'source_check',return_value=(self.checks,self.source)),mock.patch.object(check,'Path',side_effect=path),mock.patch.object(check,'_EXECUTIONS',owners),mock.patch.object(check.zipfile,'ZipFile',side_effect=lambda *args:MemoryZip(store,*args)):
            report,result=check.run_readonly(self.checks['checker_sha256'],_adb_factory=FakeAdb,_output=out)
            before=dict(store['files']);old_calls=list(calls)
            with self.assertRaises(ValueError):check.run_readonly(self.checks['checker_sha256'],_adb_factory=FakeAdb,_output=out)
            self.assertEqual(before,store['files']);self.assertEqual(old_calls,calls)
        return report,store,calls,owners
    def test_host_fake_single_command_exact_echo_and_public_pair(self):
        obj,fs,reader=self.make();value=obj.collect();report,store,calls,owners=self.host_fake(value)
        self.assertTrue(report['pass']);self.assertEqual(1,len(calls));label,args,timeout,data=calls[0]
        self.assertTrue(report['device_command_attempted']);self.assertTrue(report['device_reply_confirmed']);self.assertNotIn('device_command_sent',report)
        self.assertEqual('original-wpa-identity',label);self.assertEqual('shell',args[0]);self.assertEqual(30,timeout)
        self.assertEqual((self.source+"\nprint('MTA_REMOTE_OK')\n").encode(),data)
        self.assertIsNotNone(owners[0]['adb']);self.assertEqual(self.source,owners[0]['source'])
        self.assertEqual([['result.json','README.txt']],list(store['bundles'].values()))
        public=store['files']['HOST_SYNTHETIC_OUTPUT/result.json'].decode()
        for secret in ('PRIVATE','/run/','11111111',value['private']['identity_before']['image_sha']):self.assertNotIn(secret,public)
        self.assertEqual(b'0',store['files']['HOST_SYNTHETIC_OUTPUT/private-raw/01-original-wpa-identity.remote-exit'])
        self.assertEqual(b'',store['files']['HOST_SYNTHETIC_OUTPUT/private-raw/01-original-wpa-identity.stderr.raw'])
    def test_host_fake_missing_wlan_is_failed_fact_not_transport_success(self):
        obj,fs,reader=self.make();fs.dirs['/sys/class/net']=['lo'];report,store,calls,owners=self.host_fake(obj.collect())
        self.assertFalse(report['pass']);self.assertTrue(report['wlan_observed']);self.assertFalse(report['wlan_present'])
        self.assertEqual('wlan_absent',report['failure']['reason']);self.assertNotIn('error_class',report)
        self.assertEqual(1,len(calls));self.assertNotIn('PRIVATE',json.dumps(report))
    def test_host_fake_unknown_frame_and_host_exit_are_failures_with_raw(self):
        obj,fs,reader=self.make();value=obj.collect()
        for mode,kind in (('free_output','value_error'),('host_exit','runtime_error'),('stderr','value_error')):
            report,store,calls,owners=self.host_fake(value,mode)
            self.assertFalse(report['pass']);self.assertEqual(kind,report['error_class']);self.assertEqual(1,len(calls))
            self.assertTrue(report['device_command_attempted']);self.assertFalse(report['device_reply_confirmed'])
            self.assertIn('remote_first_error',owners[0]);self.assertNotIn('PRIVATE',json.dumps(report))
            stem='HOST_SYNTHETIC_OUTPUT/private-raw/01-original-wpa-identity'
            self.assertIn(stem+'.stdout.raw',store['files']);self.assertIn(stem+'.stderr.raw',store['files'])
            self.assertEqual(b'1' if mode=='host_exit' else b'0',store['files'][stem+'.remote-exit'])
    def test_host_fake_exit_artifact_error_preserves_first_failure_exact_refs(self):
        obj,fs,reader=self.make();value=obj.collect()
        for mode,kind in (('free_output','value_error'),('good','os_error')):
            report,store,calls,owners=self.host_fake(value,mode,True)
            self.assertFalse(report['pass']);self.assertEqual(kind,report['error_class'])
            self.assertIs(owners[0]['remote_exit_record_error'].__class__,OSError)
            if mode=='free_output':self.assertIs(owners[0]['first_error'],owners[0]['remote_first_error'])
            else:self.assertIs(owners[0]['first_error'],owners[0]['remote_exit_record_error'])
            self.assertNotIn('PRIVATE',json.dumps(report));self.assertEqual(1,len(calls))


if __name__=='__main__':unittest.main()
