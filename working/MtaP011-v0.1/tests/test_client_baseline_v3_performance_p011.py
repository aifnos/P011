"""Only new readonly performance source/Fake phases; no old tests rerun."""
import ast
import hashlib
import importlib.util
import math
from pathlib import Path
import types
import unittest
from unittest import mock

BASE=Path(__file__).absolute().parents[1]
spec=importlib.util.spec_from_file_location('v3_performance',str(BASE/'host/client_baseline_v3_performance_p011.py'))
driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)


class PerformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report,cls.rows,cls.native,cls.manifest,cls.old=driver.source_check()
        cls.source,cls.sha,cls.derived_sha=driver.build_source(cls.rows,cls.native,cls.manifest,'a'*32,cls.report['driver_sha256'])
        cls.values={};exec(cls.source[:cls.source.index(driver.TARGET)],cls.values)
        cls.bl=cls.values['modules']['mta_client_baseline'];cls.core=cls.values['modules']['mta_p2p_client_init']

    def setUp(self):
        for name in ('os.open','os.mkdir','socket.socket','subprocess.Popen','os.kill'):
            patcher=mock.patch(name,side_effect=AssertionError('no actual OS/P011/RF'))
            patcher.start();self.addCleanup(patcher.stop)

    def test_six_fixed_sites_reverse_to_exact_v3_baseline(self):
        original=next(raw for name,pin,raw in self.rows if name=='mta_client_baseline')
        raw,pin=driver.derive_baseline(original);text=raw.decode()
        for before,after in reversed(driver.REPLACEMENTS):
            self.assertEqual(text.count(after),1);text=text.replace(after,before,1)
        self.assertEqual(text.encode(),original);self.assertEqual(pin,self.derived_sha)
        self.assertEqual(hashlib.sha256(original).hexdigest(),driver.BASELINE_SHA)
        self.assertEqual(self.report['site_count'],6)
        self.assertEqual(driver.REFERENCE_SHA,'518617174571a7f9b8b295083054a44212d67cac0e173340fa4bb4e47b647122')

    def test_real_collect_snapshot_identity_and_task_failure_sites(self):
        for site in ('snapshot_identity','snapshot_tasks'):
            with self.subTest(site=site):
                obj=object.__new__(self.bl.BaselineCollector)
                obj._attempted=obj._ended=obj._pending=obj._success=False
                obj._reason='not_started';obj._timeout=10;obj._manifest=();obj._binaries={}
                obj._tickets=[];obj._observations=[];obj._rounds=[];obj._raw=[]
                obj._io=types.SimpleNamespace(validate=lambda:None);obj._now=lambda:100.
                actor=self.core.Actor(200,10,'/usr/bin/Z03','a'*64,((200,10,'S'),))
                observation=types.SimpleNamespace(boot='same',actor=actor)
                obj._proc=lambda *args,**kwargs:observation
                obj._socket=lambda *args:object();obj._generic=lambda *args:(object(),)
                obj._interfaces=lambda *args:(types.SimpleNamespace(name='wlan0',iftype=2),)
                obj._status=lambda *args:('COMPLETED',2412);obj._ipv4=lambda *args:object();obj._ipv6=lambda *args:()
                states=iter(('R','S'))
                obj._actors=lambda:(self.core.Actor(200,10,'/usr/bin/Z03','a'*64,((200,10,next(states)),)),)
                class Snapshot(object):
                    count=0
                    def __init__(self,*args):
                        self.stock_actors=args[2];self.index=Snapshot.count;Snapshot.count+=1
                    def key(self):return ('identity',self.index if site=='snapshot_identity' else 0)
                with mock.patch.object(self.bl.genl,'_family',return_value=1), \
                        mock.patch.object(self.bl,'core',types.SimpleNamespace(Snapshot=Snapshot)):
                    with self.assertRaisesRegex(self.bl.BaselineError,'snapshot_changed'):obj.collect(110.)
                note=obj._diagnostic_actor_change
                self.assertEqual(note[0],site);self.assertIs(note[1],obj._rounds[0]);self.assertIs(note[2],obj._rounds[1])
                self.assertTrue(obj._ended)
                if site=='snapshot_tasks':
                    self.assertEqual(note[1].key(),note[2].key())
                    self.assertEqual(note[1].stock_actors[0].key(),note[2].stock_actors[0].key())
                    self.assertNotEqual(note[1].stock_actors[0].tasks,note[2].stock_actors[0].tasks)

    def test_fixed_factory_ten_seconds_timings_keep_return_and_exception(self):
        created=[];clock=[100.];token=object();failure=ValueError('private Fake failure')
        def tick():clock[0]+=.01;return clock[0]
        class Collector(object):
            def __init__(self,p,budget):
                created.append((p,budget));self._manifest=(('first','a'),('second','b'))
            def _read_file(self,*args,**kwargs):return token
            def _proc(self,*args):return token
            def _actor_image(self,*args):return self._proc()
            def _actors(self,*args):return self._actor_image()
            def _interfaces(self,*args):return token
            def _status(self,*args):return token
            def _ipv4(self,*args):return token
            def _ipv6(self,*args):return token
            def collect(self,*args):
                for unused in range(2):self._read_file('first',10,binary=True)
                self._actors();self._read_file('comm',10)
                for unused in range(2):self._read_file('first',10,binary=True)
                return token
        values={'pm':types.SimpleNamespace(_AuthenticatedCollector=Collector),
            'time':types.SimpleNamespace(monotonic=tick),'math':math}
        node=next(n for n in ast.parse(driver.TARGET).body if isinstance(n,ast.FunctionDef) and n.name=='timed_collector')
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<pure timing fixture>','exec'),values)
        p=object();reader=values['timed_collector'](p,5)
        self.assertEqual(created,[(p,10)]);self.assertIs(reader.collect(110),token)
        rows=reader._diagnostic_timings
        self.assertEqual(sum(r['phase']=='manifest_binary' for r in rows),2)
        self.assertEqual(sum(r['phase']=='rehash' for r in rows),2)
        self.assertEqual(sum(r['phase']=='collect' for r in rows),1)
        self.assertGreater(next(r['elapsed'] for r in rows if r['phase']=='actors'),
            next(r['elapsed'] for r in rows if r['phase']=='proc'))
        self.assertFalse(reader._diagnostic_timing_invalid)
        class Raised(Collector):
            def _status(self,*args):raise failure
        values['pm']._AuthenticatedCollector=Raised;reader=values['timed_collector'](p,5)
        with self.assertRaises(ValueError) as caught:reader._status()
        self.assertIs(caught.exception,failure);self.assertEqual(reader._diagnostic_timings[-1]['outcome'],'raised')

    def test_readonly_ten_second_factory_source_graph_and_ast(self):
        tree=ast.parse(driver.TARGET,feature_version=(3,5))
        names={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
        self.assertFalse(names & {'mkdir','open','write','unlink','kill','spawn','start','acquire','create','publish','recover','close_resources'})
        snapshots=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='snapshot']
        self.assertEqual(len(snapshots),1);self.assertEqual(ast.literal_eval(snapshots[0].args[0].right),10)
        self.assertIn('provider._collector_factory=timed_collector',driver.TARGET)
        self.assertEqual(dict(self.old.PINS)['mta_p2p_client_init'],'f5ebf037743f9fc910a7107425119576acdea649e16cf9e0660c0e9e257a607e')
        self.assertEqual(dict(self.old.PINS)['mta_client_baseline'],driver.BASELINE_SHA)
        self.assertEqual(self.report['source_count'],19)
        ast.parse(self.source,feature_version=(3,5));ast.parse((BASE/'host/client_baseline_v3_performance_p011.py').read_text(),feature_version=(3,5))
        self.assertLessEqual(len(self.source.encode()),4*1024*1024)
        self.assertLessEqual(max(len(line.encode()) for line in self.source.splitlines()),2048)

    def test_default_source_only_and_old_production_budgets_untouched(self):
        with mock.patch.object(driver,'source_check',return_value=({'source_check_pass':True},None,None,None,None)), \
                mock.patch.object(driver,'execute',side_effect=AssertionError('no device')),mock.patch('builtins.print'):
            self.assertEqual(driver.main([]),0)
        original=(BASE/'host/client_baseline_diagnostic_p011.py').read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(),'5f37b3654c5aca3a1a5737e943f8eea1f9365c5edf7c187691e2d32f9b3c8023')
        provider=(BASE/'runtime/mta_client_linux_provider.py').read_bytes()
        self.assertEqual(hashlib.sha256(provider).hexdigest(),'8996ae6aa82e48170514f61fc301a83532cf28a20f385153ff41c1e68b236544')
        self.assertIn(b'self._collector_factory(self, min(5, self._now(deadline)))',provider)


if __name__=='__main__':unittest.main()
