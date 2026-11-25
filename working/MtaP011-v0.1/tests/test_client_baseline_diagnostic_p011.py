"""New fixed READONLY diagnostic: pure source and Fake I/O, never P011."""
import ast
import base64
import builtins
import errno
import hashlib
import importlib.util
from pathlib import Path
import re
import stat
import types
import unittest
from unittest import mock

import test_client_init_p011_host as prior

BASE = Path(__file__).absolute().parents[1]
spec = importlib.util.spec_from_file_location('fixed_baseline_diagnostic',
    str(BASE / 'host/client_baseline_diagnostic_p011.py'))
driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)


class ClosedIo(object):
    def fstat(self, fd): raise OSError(errno.EBADF, 'Fake closed original')


class DiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # PC pinned-source reads only. No actual child/socket/native operation.
        cls.report, cls.rows, cls.native, cls.manifest, cls.old = driver.source_check()
        cls.source, cls.candidate, cls.derived_sha = driver.build_source(
            cls.rows, cls.native, cls.manifest, 'a'*32, cls.report['driver_sha256'])
        cls.values = {}
        exec(cls.source[:cls.source.index(driver.TARGET)], cls.values)
        cls.modules = cls.values['modules']
        cls.baseline = cls.modules['mta_client_baseline']
        cls.core = cls.modules['mta_p2p_client_init']
        cls.proc = cls.modules['mta_client_proc']

    def setUp(self):
        for name in ('subprocess.Popen', 'socket.socket', 'os.kill', 'os.mkdir', 'os.open'):
            patcher = mock.patch(name, side_effect=AssertionError('no actual device/OS action'))
            patcher.start(); self.addCleanup(patcher.stop)

    def actor(self, state='S', start=10):
        return self.core.Actor(200, start, '/usr/bin/Z03', 'c'*64, ((200,start,state),))

    def observation(self, actor=None, boot='same'):
        return self.proc.ProcObservation('live_actor','read_closed','complete',boot,
            actor or self.actor(),False,(),True,2,(),1,1,False,1)

    def image_collector(self, left, right):
        bl=self.baseline; instance=object.__new__(bl.BaselineCollector)
        data=b'Fake pinned stock image'; digest=hashlib.sha256(data).hexdigest()
        meta=(1,2,stat.S_IFREG|0o755,0,0,1,len(data),1,1)
        row={'kind':'fd','value':None,'fd':7,'unknown':False,'attempted':False,
            'closed':False,'kill_attempted':False,'waited':False,'pipes':(),'pipe_refs_valid':True}
        class Io(object):
            def __init__(self): self.parts=[data,b''];self.closed=False;self.calls=[]
            def fstat(self, fd):
                if self.closed: raise OSError(errno.EBADF,'Fake closed')
                return types.SimpleNamespace(**dict(zip(('st_dev','st_ino','st_mode',
                    'st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'),meta)))
            def read(self, fd, size):return self.parts.pop(0)
            def close(self, fd):self.calls.append(('close',fd));self.closed=True
        instance._io=Io();instance._manifest=((left.exe,digest),)
        instance._binaries={left.exe:(row,meta,())};instance._raw=[];instance._pending=False
        instance._open=lambda *args:row;instance._proc=lambda *args:right;instance._now=lambda:100.
        return instance,row

    def collect_fixture(self, site):
        bl=self.baseline; obj=object.__new__(bl.BaselineCollector)
        obj._attempted=obj._ended=obj._pending=obj._success=False
        obj._reason='not_started';obj._timeout=5;obj._manifest=();obj._binaries={}
        obj._tickets=[];obj._observations=[];obj._rounds=[];obj._raw=[]
        obj._io=types.SimpleNamespace(validate=lambda:None);obj._now=lambda:100.
        same=self.observation();changed=self.observation(self.actor(start=11))
        values=[same,changed] if site=='self_round' else [same,same,same,changed if site=='self_final' else same]
        def read(*args,**kwargs):
            value=values.pop(0);obj._observations.append(value);return value
        obj._proc=read;obj._socket=lambda protocol:object();obj._generic=lambda *args:(object(),)
        obj._interfaces=lambda *args:(types.SimpleNamespace(name='wlan0',iftype=2),)
        obj._status=lambda *args:('COMPLETED',2412);obj._ipv4=lambda *args:object();obj._ipv6=lambda *args:()
        def actors():
            if site=='observation_boot':obj._observations.append(self.observation(boot='different'))
            return (self.actor(),)
        obj._actors=actors
        class Snapshot(object):
            def __init__(self,*args):self.stock_actors=args[2]
            def key(self):return ('same-structural-baseline',)
        return obj,Snapshot

    def run_target(self, *, closed=True, site='actor_image', pending=False):
        fixture=prior.TargetFixture(pending=pending);core=self.core;proc=self.proc
        left,right=self.actor('R'),self.observation(self.actor('S'))
        fixture.actor=core.Actor(100,10,'/python','d'*64,((100,10,'S'),))
        class Reader(object):
            def __init__(self,timeout):
                self.closed=True;self._active=self._pending=False;self._files=self._closed=0
                self._fd_refs=[];self._open_attempt=None
            def read_self(self):
                return proc.ProcObservation('live_actor','read_closed','complete','same',
                    fixture.actor,False,(),True,2,(),1,1,False,1)
            def read_actor(self,*args):return self.read_self()
        meta=(1,2,stat.S_IFREG|0o755,0,0,1,8,1,1)
        row={'kind':'fd','fd':7,'unknown':False,'attempted':True,'closed':closed,
            'kill_attempted':False,'waited':False,'pipe_refs_valid':True}
        collector=types.SimpleNamespace(_io=ClosedIo(),_reader=Reader(3),_tickets=[row],
            _observations=[self.observation(left),right],_rounds=[],_binaries={},
            _raw=[('file','/proc/200/comm',b'Z03\n',meta),
                ('actor_image','/proc/200/exe','e'*64,meta),('netlink',b'packet',(),0,(0,0))],
            _packets=1,_ended=True,_pending=not closed,status_readers=[],
            _diagnostic_actor_change=(site,left,right) if site=='actor_image' else None)
        collector.status=lambda:{'reason':'actor_changed','resource_pending':not closed}
        fixture.modules['mta_client_proc']=types.SimpleNamespace(ProcReader=Reader)
        fixture.modules['mta_client_baseline']=self.baseline
        f=fixture.modules['mta_client_executor']
        class ExecutorError(ValueError):pass
        f.ExecutorError=ExecutorError
        class Provider(object):
            def __init__(self):self._collectors=[];self._proc_calls=[]
            def executor(self,deadline):fixture.calls.append('executor')
            def snapshot(self,deadline):
                fixture.calls.append('snapshot');self._collectors.append({'reader':collector,'unknown':True,'value':None})
                raise self_baseline.BaselineError('actor_changed')
        self_baseline=self.baseline
        fixture.modules['mta_client_linux_provider'].assemble=lambda manifest:(Provider(),None,None,None,None)
        for name in ('mkdir','open','write','fsync','fchmod','lseek'):
            setattr(fixture.os,name,lambda *args:(_ for _ in ()).throw(AssertionError('no mutation')))
        values={k:v for k,v in self.values.items() if k not in ('__builtins__','modules')}
        values.update(modules=fixture.modules,re=re)
        imports={'os':fixture.os,'time':types.SimpleNamespace(monotonic=lambda:fixture.clock),
            'sys':types.SimpleNamespace(flags=types.SimpleNamespace(optimize=0),version_info=(3,5,5))}
        importer=builtins.__import__;output=[]
        def fake_import(name,*args,**kwargs):return imports[name] if name in imports else importer(name,*args,**kwargs)
        values['__builtins__']=dict(vars(builtins),__import__=fake_import,print=lambda text:output.append(text))
        exec(driver.TARGET,values)
        return ast.literal_eval(output[-1][7:]),fixture,values

    def test_four_site_copy_has_exact_reverse_and_original_conditions(self):
        original=next(raw for name,pin,raw in self.rows if name=='mta_client_baseline')
        derived,digest=driver.derive_baseline(original);back=derived.decode('utf-8')
        for before,after in reversed(driver.REPLACEMENTS):
            self.assertEqual(back.count(after),1);back=back.replace(after,before,1)
        self.assertEqual(back.encode('utf-8'),original)
        self.assertEqual(digest,self.derived_sha)
        self.assertEqual(self.report['baseline_original_sha256'],driver.BASELINE_SHA)

    def test_changed_original_or_fragment_rejected_before_execution(self):
        original=next(raw for name,pin,raw in self.rows if name=='mta_client_baseline')
        with self.assertRaisesRegex(ValueError,'baseline_pin'):driver.derive_baseline(original+b'\n')
        with mock.patch.object(driver,'REPLACEMENTS',driver.REPLACEMENTS+(driver.REPLACEMENTS[0],)):
            with self.assertRaisesRegex(ValueError,'baseline_fragment'):driver.derive_baseline(original)

    def test_actual_actor_image_predicate_records_state_only_but_still_fails(self):
        left,right=self.actor('R'),self.observation(self.actor('S'))
        obj,row=self.image_collector(left,right)
        with self.assertRaisesRegex(self.baseline.BaselineError,'actor_changed'):obj._actor_image(left)
        self.assertEqual(obj._diagnostic_actor_change,('actor_image',left,right))
        self.assertEqual(left.key(),right.actor.key());self.assertTrue(left.live() and right.actor.live())
        self.assertNotEqual(left.tasks,right.actor.tasks);self.assertTrue(row['closed'])
        self.assertEqual(obj._io.calls,[('close',7)])

    def test_actor_image_identity_difference_not_forged_state_only(self):
        left,right=self.actor(),self.observation(self.actor(start=11))
        obj,row=self.image_collector(left,right)
        with self.assertRaisesRegex(self.baseline.BaselineError,'actor_changed'):obj._actor_image(left)
        self.assertNotEqual(left.key(),right.actor.key());self.assertIs(obj._diagnostic_actor_change[2],right)

    def test_actor_image_equal_comparison_records_no_failure_site(self):
        left=self.actor();obj,row=self.image_collector(left,self.observation(left))
        obj._actor_image(left);self.assertFalse(hasattr(obj,'_diagnostic_actor_change'));self.assertTrue(row['closed'])

    def test_actual_collect_self_round_site(self):
        self.check_collect_site('self_round')

    def test_actual_collect_observation_boot_site(self):
        self.check_collect_site('observation_boot')

    def test_actual_collect_self_final_site(self):
        self.check_collect_site('self_final')

    def check_collect_site(self,site):
        obj,Snapshot=self.collect_fixture(site)
        with mock.patch.object(self.baseline.genl,'_family',return_value=1), \
                mock.patch.object(self.baseline,'core',types.SimpleNamespace(Snapshot=Snapshot)):
            with self.assertRaisesRegex(self.baseline.BaselineError,'actor_changed'):obj.collect(105.)
        self.assertEqual(obj._diagnostic_actor_change[0],site);self.assertTrue(obj._ended)

    def test_target_stops_at_first_snapshot_retains_original_failed_row(self):
        result,fixture,values=self.run_target()
        self.assertEqual(fixture.calls,['validate','executor','snapshot'])
        public,private=result['public'],result['private']
        self.assertTrue(public['diagnostic_complete']);self.assertTrue(public['resource_pending'])
        self.assertTrue(public['collector_inventory_closed']);self.assertEqual(public['failure_site'],'actor_image')
        self.assertTrue(all(public[k] for k in ('actor_key_equal','actors_live','actor_tasks_differ','only_task_states_differ')))
        self.assertEqual(private['provider_observers'],({'value_present':False,'unknown':True},))
        self.assertEqual(public['comm_read_count'],1);self.assertEqual(public['baseline_datagram_count'],1)
        self.assertEqual(public['collector_fd_ebadf_count'],1)
        self.assertFalse(public['snapshot_returned']);self.assertFalse(public['rf_requested'])
        self.assertIn('actor_changed',private['errors'][0]['traceback'])

    def test_unknown_close_is_not_diagnostic_success_or_retried(self):
        result,fixture,unused=self.run_target(closed=False)
        self.assertFalse(result['public']['diagnostic_complete']);self.assertTrue(result['public']['resource_pending'])
        self.assertEqual(fixture.calls,['validate','executor','snapshot'])
        self.assertEqual(result['private']['collector']['tickets'][0]['closed'],False)

    def test_existing_pending_blocks_before_python_and_assemble(self):
        result,fixture,unused=self.run_target(pending=True)
        self.assertEqual(result['public']['reason'],'pending_blocked');self.assertEqual(fixture.calls,['validate'])
        self.assertIsNone(result['private']['collector']);self.assertFalse(result['public']['rf_requested'])

    def test_private_bytes_reversible_but_elf_is_digest_only(self):
        result,fixture,values=self.run_target()
        raw=result['private']['collector']['raw'][0][2]
        self.assertEqual(base64.b64decode(raw['bytes_b64']),b'Z03\n')
        self.assertEqual(values['projection'](fixture.os.python),{
            'binary_digest':hashlib.sha256(fixture.os.python).hexdigest(),'length':len(fixture.os.python)})
        self.assertNotIn('bytes_b64',result['private']['python_image'])
        self.assertNotIn('WPA_ENCODED',self.source)
        self.assertNotIn(base64.b64encode(self.native).decode('ascii'),self.source)

    def test_strict_private_frame_and_safe_public_projection(self):
        result,unused,values=self.run_target()
        text=('RESULT='+repr(result)+'\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n').encode('utf-8')
        echo=b'# exact transmitted source\n'
        parsed=driver.parse({'stdout':(echo+text).replace(b'\n',b'\r\r\n'),'stderr':b'','host_exit':0},echo)
        self.assertEqual(parsed['public'],result['public'])
        self.assertFalse(set(parsed['public']) & {'pid','path','fd','ip','ssid','tasks','traceback'})
        for extra in (b'unknown\n',b'MTA_REMOTE_OK\n'):
            with self.assertRaisesRegex(ValueError,'remote_frame'):
                driver.parse({'stdout':extra+text,'stderr':b'','host_exit':0})
        for key in ('rf_requested','send_available','restoration_verified'):
            changed={'public':dict(result['public'],**{key:True}),'private':result['private']}
            with self.assertRaisesRegex(ValueError,'public_shape'):
                driver.parse({'stdout':('RESULT='+repr(changed)+'\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n').encode(),
                    'stderr':b'','host_exit':0})

    def test_default_source_only_no_adb_or_execute(self):
        with mock.patch.object(driver,'source_check',return_value=({'source_check_pass':True},None,None,None,None)), \
                mock.patch.object(driver,'execute',side_effect=AssertionError('no device')),mock.patch('builtins.print'):
            self.assertEqual(driver.main([]),0)

    def test_actual_graph_and_target_ast_forbid_mutation_calls(self):
        self.assertEqual(self.report['source_count'],19);self.assertEqual(self.report['site_count'],4)
        names=dict(self.old.PINS)
        self.assertEqual(names['mta_client_executor'],'9cf0226e76254639c8fb7ab2638f6270ee0091b2485d49e00c0beff47d8f8602')
        self.assertEqual(names['mta_client_process_owner'],'219156a42a6598fb3e6669f191c269bfe3ac75da8f2f95190fb23b3867794b76')
        tree=ast.parse(driver.TARGET,feature_version=(3,5))
        calls={node.func.attr for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute)}
        self.assertFalse(calls & {'mkdir','open','write','unlink','kill','spawn','start','acquire','create','publish','recover','close_resources'})
        self.assertEqual(sum(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='snapshot' for n in ast.walk(tree)),1)
        ast.parse(self.source,feature_version=(3,5));ast.parse((BASE/'host/client_baseline_diagnostic_p011.py').read_text(),feature_version=(3,5))
        self.assertLessEqual(len(self.source.encode()),4*1024*1024)
        self.assertLessEqual(max(len(line.encode()) for line in self.source.splitlines()),2048)
        self.assertFalse(any(isinstance(n,ast.Assert) for n in ast.walk(ast.parse(self.source))))


if __name__=='__main__':unittest.main()
