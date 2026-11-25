"""New v3 multiplicity/source graph tests; pure records/Fake reads only."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

BASE=Path(__file__).absolute().parents[1]
spec=importlib.util.spec_from_file_location('client_baseline_v3_host',str(BASE/'host/client_init_baseline_v3_p011.py'))
driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
ROUTE_WIDTHS=(32,2,32,2,32,8,8,8,8)
ADDRESS_WIDTHS=(32,'2,8',2,2,2)
ROUTE_A=('fe80'+'0'*28,'40','0'*32,'00','0'*32,'00000100','00000001','00000000','00000001','wlan0')
ROUTE_B=('ff'+'0'*30,'08','0'*32,'00','0'*32,'00000100','00000001','00000000','00000001','wlan0')
ADDRESS=('fe80'+'0'*28,'00000016','40','20','80','wlan0')


class BaselineV3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Only PC reads/pure pinned-memory module load. No target operation.
        cls.report,cls.rows,cls.native,cls.manifest,unused=driver.source_check()
        cls.source,cls.sha=driver.build_source(cls.rows,cls.native,cls.manifest,'a'*32,cls.report['driver_sha256'])
        values={};exec(cls.source[:cls.source.index(driver.TARGET)],values)
        cls.modules=values['modules'];cls.core=cls.modules['mta_p2p_client_init']
        cls.bl=cls.modules['mta_client_baseline'];cls.ip=cls.modules['mta_ip']
        cls.codec=cls.modules['mta_client_journal_codec']
        cls.old_bl=(BASE/'runtime/mta_client_baseline.py').read_text(encoding='utf-8')
        cls.old_core=(BASE/'runtime/mta_p2p_client_init.py').read_text(encoding='utf-8')
        cls.old_host=(BASE/'host/client_init_nlink2_p011.py').read_text(encoding='utf-8')

    def setUp(self):
        for name in ('os.open','os.mkdir','socket.socket','subprocess.Popen','os.kill'):
            patcher=mock.patch(name,side_effect=AssertionError('no actual OS/device/RF'))
            patcher.start();self.addCleanup(patcher.stop)

    def snapshot(self,routes=(),addresses=(),state='S'):
        c=self.core;ip=self.ip;sta=c.Origin(0,1,22,'wlan0',2)
        stock=tuple(c.Actor(pid,100,path,'b'*64,((pid,100,state if pid==11 else 'S'),))
            for pid,path in ((11,'/usr/bin/Z03'),(12,'/usr/bin/control_engine'),(13,'/usr/bin/weston')))
        ipv4=ip.IpSnapshot((),(),(ip.RuleRecord(0,255),ip.RuleRecord(32766,254),ip.RuleRecord(32767,253)))
        return c.Snapshot('12345678-1234-1234-1234-123456789abc',c.STOCK_PINS,stock,sta,'c'*64,
            2412,(sta,),ipv4,addresses,routes,True)

    def ipv6(self,rows,path='/proc/net/ipv6_route',widths=ROUTE_WIDTHS):
        obj=object.__new__(self.bl.BaselineCollector)
        raw=rows if type(rows) is bytes else ('\n'.join(' '.join(r) for r in rows)+'\n').encode('ascii')
        obj._read_file=lambda actual,limit:(raw,None,None)
        return obj._ipv6(path,widths)

    def test_route_multiplicity_and_order_are_preserved_exactly(self):
        rows=(ROUTE_A,ROUTE_B,ROUTE_A)
        self.assertEqual(self.ipv6(rows),rows)
        snap=self.snapshot(rows);self.assertIs(snap.ipv6_routes,rows)
        self.assertNotEqual(snap.key(),self.snapshot((ROUTE_A,ROUTE_B)).key())
        self.assertEqual(sum(r==ROUTE_A for r in snap.key()[-1]),2)

    def test_route_codec_keeps_complete_original_tuple_and_cas(self):
        routes=(ROUTE_A,ROUTE_B,ROUTE_A)
        record=self.core.Journal(self.core.Identity('a'*64),'prepared',self.snapshot(routes),120.)
        raw=self.codec.encode_journal(record);decoded=self.codec.decode_journal(raw)
        self.assertEqual(decoded.baseline.ipv6_routes,routes)
        self.assertEqual(self.codec.encode_journal(decoded),raw)
        self.assertTrue(self.core._same_journal(record,decoded))

    def test_address_and_unknown_path_duplicates_still_rejected(self):
        with self.assertRaisesRegex(self.bl.BaselineError,'ipv6_format'):
            self.ipv6((ADDRESS,ADDRESS),'/proc/net/if_inet6',ADDRESS_WIDTHS)
        with self.assertRaisesRegex(self.bl.BaselineError,'ipv6_format'):
            self.ipv6((ROUTE_A,ROUTE_A),'/proc/net/not_a_route')
        with self.assertRaisesRegex(self.core.ClientInitError,'invalid_snapshot'):
            self.snapshot((ROUTE_A,),addresses=(ADDRESS,ADDRESS))

    def test_route_original_ascii_width_ifname_and_budget_gates_still_reject(self):
        bad=(b'\xff\n',b'one field\n',
            (' '.join(('FE80'+'0'*28,)+ROUTE_A[1:])+'\n').encode(),
            (' '.join(ROUTE_A[:-1]+('../wlan0',))+'\n').encode())
        for raw in bad:
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(self.bl.BaselineError,'ipv6_format'):self.ipv6(raw)
        with self.assertRaisesRegex(self.bl.BaselineError,'ipv6_format'):
            self.ipv6((ROUTE_A,)*(self.bl.MAX_ROWS+1))
        with self.assertRaisesRegex(self.core.ClientInitError,'invalid_snapshot'):
            self.snapshot((ROUTE_A,)*4097)

    def test_core_shape_and_other_uniqueness_gates_unchanged(self):
        for rows in ([ROUTE_A,ROUTE_A],(list(ROUTE_A),),(ROUTE_A[:-1],),
                     (ROUTE_A[:-1]+('bad\n',),)):
            with self.subTest(rows=rows):
                with self.assertRaisesRegex(self.core.ClientInitError,'invalid_snapshot'):self.snapshot(rows)
        with self.assertRaisesRegex(self.core.ClientInitError,'invalid_snapshot'):
            self.core._rows((ADDRESS,ADDRESS),6)
        with self.assertRaisesRegex(self.core.ClientInitError,'invalid_snapshot'):
            self.core._rows((ROUTE_A,),10,_unique=1)

    def test_cas_still_sensitive_to_raw_task_state(self):
        c=self.core;left=c.Journal(c.Identity('a'*64),'prepared',self.snapshot((ROUTE_A,ROUTE_A),state='R'),120.)
        right=c.Journal(c.Identity('a'*64),'prepared',self.snapshot((ROUTE_A,ROUTE_A),state='S'),120.)
        self.assertEqual(left.key(),right.key());self.assertFalse(c._same_journal(left,right))
        self.assertNotEqual(self.codec.encode_journal(left),self.codec.encode_journal(right))

    def test_candidate_copies_reverse_to_exact_pinned_originals(self):
        def reverse(text,pairs):
            for old,new in reversed(pairs):
                self.assertEqual(text.count(new),1);text=text.replace(new,old,1)
            return text
        bl=(BASE/'candidate/client-baseline-v3/runtime/mta_client_baseline.py').read_text(encoding='utf-8')
        before="        if len(rows) > MAX_ROWS or len(set(rows)) != len(rows): _fail('ipv6_format')"
        after="        if len(rows) > MAX_ROWS or (path != '/proc/net/ipv6_route' and len(set(rows)) != len(rows)):\n            _fail('ipv6_format')"
        self.assertEqual(reverse(bl,((before,after),)),self.old_bl)
        core=(BASE/'candidate/client-baseline-v3/runtime/mta_p2p_client_init.py').read_text(encoding='utf-8')
        pairs=(('def _rows(rows, width, limit=4096):','def _rows(rows, width, limit=4096, _unique=True):'),
            ('    if type(rows) is not tuple or len(rows) > limit or any(type(row) is not tuple or len(row) != width',
             '    if type(_unique) is not bool or type(rows) is not tuple or len(rows) > limit or any(type(row) is not tuple or len(row) != width'),
            ('            for row in rows) or len(set(rows)) != len(rows):',
             '            for row in rows) or (_unique and len(set(rows)) != len(rows)):'),
            ("('ipv6_routes', _rows(ipv6_routes, 10))","('ipv6_routes', _rows(ipv6_routes, 10, _unique=False))"))
        self.assertEqual(reverse(core,pairs),self.old_core)
        self.assertEqual(hashlib.sha256(self.old_bl.encode()).hexdigest(),'ce8fe17b60964cf9b421296eef033d1dde19f8a4118de12d7f3922133ee13f08')
        self.assertEqual(hashlib.sha256(self.old_core.encode()).hexdigest(),'ec2d927c50bf2946614990bdd9fe1d69ce5538047573d9a4d885a3914b0f85f1')

    def test_dynamic_actor_checks_and_entire_target_are_untouched(self):
        def functions(text):return {n.name:ast.dump(n,include_attributes=False) for n in ast.walk(ast.parse(text)) if isinstance(n,ast.FunctionDef)}
        current=(BASE/'candidate/client-baseline-v3/runtime/mta_client_baseline.py').read_text()
        self.assertEqual(functions(current)['_actor_image'],functions(self.old_bl)['_actor_image'])
        self.assertEqual(functions(current)['collect'],functions(self.old_bl)['collect'])
        old_target=next(ast.literal_eval(n.value) for n in ast.parse(self.old_host).body
            if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='TARGET')
        self.assertEqual(driver.TARGET,old_target)
        current=(BASE/'candidate/client-baseline-v3/runtime/mta_p2p_client_init.py').read_text()
        for name in ('_same_journal','_ipv4','key'):
            self.assertEqual(functions(current)[name],functions(self.old_core)[name])

    def test_new_graph_only_two_route_copies_plus_existing_nlink2_pair(self):
        expected={'mta_client_baseline','mta_p2p_client_init','mta_client_executor','mta_client_process_owner'}
        self.assertEqual(set(driver.SOURCE_LOCATIONS),expected)
        self.assertEqual(sum(driver.SOURCE_LOCATIONS.get(name,BASE/'runtime'/(name+'.py')).parent==BASE/'runtime'
            for name,pin in driver.PINS),15)
        for name,pin,raw in self.rows:self.assertEqual(hashlib.sha256(raw).hexdigest(),pin)
        self.assertEqual(dict(driver.PINS)['mta_client_executor'],'9cf0226e76254639c8fb7ab2638f6270ee0091b2485d49e00c0beff47d8f8602')
        self.assertEqual(dict(driver.PINS)['mta_client_process_owner'],'219156a42a6598fb3e6669f191c269bfe3ac75da8f2f95190fb23b3867794b76')
        self.assertEqual(self.report['source_count'],19)
        self.assertFalse(self.report['send_available']);self.assertFalse(self.report['receive_available'])

    def test_new_source_python35_and_default_no_device(self):
        ast.parse(self.source,feature_version=(3,5))
        for path in ('host/client_init_baseline_v3_p011.py','candidate/client-baseline-v3/runtime/mta_client_baseline.py',
                     'candidate/client-baseline-v3/runtime/mta_p2p_client_init.py'):
            ast.parse((BASE/path).read_text(),feature_version=(3,5))
        self.assertLessEqual(len(self.source.encode()),driver.MAX_SOURCE)
        self.assertLessEqual(max(len(line.encode()) for line in self.source.splitlines()),2048)
        with mock.patch.object(driver,'source_check',return_value=({'source_check_pass':True},None,None,None,None)), \
                mock.patch.object(driver,'execute',side_effect=AssertionError('no device')),mock.patch('builtins.print'):
            self.assertEqual(driver.main([]),0)


if __name__=='__main__':unittest.main()
