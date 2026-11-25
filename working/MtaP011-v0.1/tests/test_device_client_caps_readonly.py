"""HOST fake ADB only: never executes the device checker or opens a socket."""
import ast
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import types
import zipfile
import zlib

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'host'))
import device_client_caps_readonly as h
import device_probe as probe


def baseline(station=True):
    actors=[{'name':n,'pid':i,'start':100,'exe':'/usr/bin/'+n,'argv':b'SECRET_ARGV\0','tasks':((i,100),)}
            for i,n in enumerate(('Z03','control_engine','weston'),11)]
    interface=lambda name,index:(name,(str(index).encode()+b'\n',str(index).encode()+b'\n',b'1\n',b'0x1003\n',b'up\n',b'02:11:22:33:44:55\n'),'../../devices/SECRET_ORIGIN')
    return {'hashes':dict(h.STOCK_PINS),'actors':actors,'interfaces':[interface('lo',1)]+([interface('wlan0',22)] if station else []),
        'boot':b'12345678-1234-1234-1234-123456789abc\n','route4':b'SECRET_PRIVATE_ROUTE4','address6':b'SECRET_ADDRESS6','route6':b'SECRET_ROUTE6'}


def caps_result():
    summary={k:True for k in h.CAP_BOOLS};summary.update({k:1 for k in h.CAP_COUNTS})
    summary.update({'iftypes':[2,8,9],'software_iftypes':[],'limit_iftypes':[2,8,9]})
    status={k:True for k in h.STATUS_BOOLS};status.update(resource_pending=False,datagram_count=3,message_count=4,unassessed_count=2,reason='read_closed')
    private={'datagrams':((1,b'SECRET_DATAGRAM',(),0,(0,0)),)*3,'requests':(b'SECRET_REQUEST',)*3,
        'wiphy_messages':(b'SECRET_WIPHY',),'unassessed':((0,2,0,b'SECRET_SSID'),)*2,'decoded':(b'SECRET_DECODED',),'traceback':None}
    return {'status':status,'caps':summary,'failure':{'stage':'complete','class':'none','errno':0},'private':private}


def phy_failure(traceback_text='Traceback (most recent call last):\nSECRET_TRACEBACK\nValueError: SECRET_PHY\n'):
    summary={k:False for k in h.CAP_BOOLS};summary.update({k:0 for k in h.CAP_COUNTS});summary.update({k:[] for k in h.TYPE_SETS})
    return {'status':None,'caps':summary,'failure':{'stage':'phy','class':'value_error','errno':0},
        'private':{'datagrams':(),'requests':(),'wiphy_messages':(),'unassessed':(),'decoded':None,'traceback':traceback_text}}


def frame(value):return ('RESULT='+repr(value)+'\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n').encode('utf-8')


class FakeAdb:
    instances=[];before=None;after=None;caps=None;fail_label=None
    def __init__(self,directory):
        self.directory=Path(directory);self.directory.mkdir(parents=True)
        self.index=0;self.calls=[];self.instances.append(self)
    def run(self,label,args,timeout=30,input_data=None):
        self.index+=1;self.calls.append((label,args,timeout,input_data))
        if args[0]!='shell' or not args[1].startswith('python3 -B -c '):raise AssertionError('not_fixed_python')
        value=self.before if label.startswith('before') else self.after if label.startswith('after') else self.caps
        raw=frame(value)
        # Model strict same-source PTY echo without executing any Python.
        if input_data is not None:raw=input_data.replace(b'\n',b'\r\r\n')+raw
        stem=self.directory/('%02d-%s'%(self.index,label))
        Path(str(stem)+'.stdout.raw').write_bytes(raw);Path(str(stem)+'.stderr.raw').write_bytes(b'SECRET_STDERR')
        failed=label==self.fail_label
        Path(str(stem)+'.host-exit').write_text('9' if failed else '0')
        if failed:raise RuntimeError('SECRET_HOST_ERROR')
        return raw


class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.socket_guard=patch.object(socket,'socket',side_effect=AssertionError('actual_socket_forbidden'));self.socket_guard.start();self.addCleanup(self.socket_guard.stop)
        self.process_guard=patch.object(subprocess,'run',side_effect=AssertionError('actual_adb_forbidden'));self.process_guard.start();self.addCleanup(self.process_guard.stop)
        FakeAdb.instances=[];FakeAdb.before=baseline();FakeAdb.after=baseline();FakeAdb.caps=caps_result();FakeAdb.fail_label=None

    def run_fake(self):
        checks,_=h.source_check()
        return h.run_reviewed(checks['checker_sha256'],Path(self.tmp.name)/'mock',FakeAdb)

    def test_default_source_only_never_constructs_adb(self):
        with patch.object(h,'run_reviewed',side_effect=AssertionError('execution_forbidden')),patch('sys.stdout',new=io.StringIO()):
            self.assertEqual(0,h.main([]))
        self.assertEqual([],FakeAdb.instances)

    def test_execute_missing_pin_and_pin_without_mode_rejected(self):
        with patch('sys.stderr',new=io.StringIO()):
            for args in (['--execute-reviewed'],['--expected-checker-sha256','a'*64],['--interface','wlan0']):
                with self.assertRaises(SystemExit):h.main(args)

    def test_wrong_checker_pin_rejected_before_target_or_output(self):
        destination=Path(self.tmp.name)/'never'
        with self.assertRaises(ValueError):h.run_reviewed('a'*64,destination,FakeAdb)
        self.assertEqual([],FakeAdb.instances);self.assertFalse(destination.exists())

    def test_dependency_wrong_pin_fails_before_execution(self):
        with patch.object(h,'MODULE_PINS',((h.MODULE_PINS[0][0],'a'*64),h.MODULE_PINS[1])):
            with self.assertRaises(ValueError):h.source_check()
        self.assertEqual([],FakeAdb.instances)

    def test_pinned_memory_modules_python35_no_device_writes(self):
        checks,sources=h.source_check()
        self.assertEqual(hashlib.sha256(Path(h.__file__).read_bytes()).hexdigest(),checks['checker_sha256'])
        for source in sources:
            tree=ast.parse(source,feature_version=(3,5))
            self.assertFalse(any(isinstance(n,ast.Assert) for n in ast.walk(tree)))
            calls=[n.func.id for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)]
            self.assertFalse(set(calls)&{'system','Popen','unlink','chmod','chown','remove'})
            for node in ast.walk(tree):
                if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='open':self.assertEqual('rb',node.args[1].value)
        tree=ast.parse(sources[1]);reads=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='reader' and n.func.attr=='read']
        self.assertEqual(1,len(reads));self.assertIn("timeout=5.0",sources[1]);self.assertIn('types.ModuleType(name)',sources[1]);self.assertNotIn('subprocess',sources[0])

    def test_unique_phy_helpers_fail_closed_not_guess(self):
        namespace={'re':re};exec(h.PHY,namespace)
        self.assertEqual('phy0',namespace['phy_name'](['phy0']));self.assertEqual(0,namespace['phy_index']('phy0',b'0\n'))
        for names in ([],['phy0','phy1'],['phy01'],['PHY0'],['phy4294967296'],['../phy0'],('phy0',),[True]):
            with self.assertRaises(ValueError):namespace['phy_name'](names)
        for raw in (b'1\n',b'00\n',b'0\x00',b'0\nsecret',b'-1',0):
            with self.assertRaises(ValueError):namespace['phy_index']('phy0',raw)

    def test_echo_exact_crcrlf_and_strict_marker_envelope(self):
        echo=b'print(123)\nprint(\'MTA_REMOTE_OK\')\n'
        raw=echo.replace(b'\n',b'\r\r\n')+frame({'count':1}).replace(b'\n',b'\r\n')
        self.assertEqual({'count':1},h._parse(raw,echo))
        for bad in (raw.replace(b'123',b'124',1),raw[len(echo)//2:],b'unknown\n'+raw,raw+b'MTA_REMOTE_OK\n',frame({}).replace(b'EXIT=0',b'EXIT=9')):
            with self.assertRaises((ValueError,SyntaxError)):h._parse(bad,echo)

    def test_target_phy_failure_traceback_only_private_one_result_line(self):
        namespace={'re':re,'sys':sys,'os':types.SimpleNamespace(listdir=lambda path:[]),'budget':lambda:1.0,
            'PINNED_MODULES':(),'CAP_BOOLS':h.CAP_BOOLS,'CAP_COUNTS':h.CAP_COUNTS,'TYPE_SETS':h.TYPE_SETS}
        exec(h.PHY,namespace)
        stdout,stderr=io.StringIO(),io.StringIO()
        with patch('sys.stdout',new=stdout),patch('sys.stderr',new=stderr):exec(h.CAPS_BODY,namespace)
        self.assertEqual('',stderr.getvalue());self.assertEqual(1,len(stdout.getvalue().splitlines()))
        value=h._parse((stdout.getvalue()+'MTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n').encode('utf-8'))
        self.assertEqual({'stage':'phy','class':'value_error','errno':0},value['failure']);self.assertIsNone(value['status'])
        self.assertIn('Traceback (most recent call last):',value['private']['traceback'])
        self.assertIn('ValueError: phy_selection',value['private']['traceback'])
        self.assertFalse(h._caps_result(value)['pass'])

    def test_phy_failure_complete_pty_frame_strict_private_result(self):
        _,sources=h.source_check();echo=(sources[1]+"\nprint('MTA_REMOTE_OK')\n").encode('utf-8')
        value=phy_failure('Traceback (most recent call last):\nSECRET_TRACEBACK\nRESULT={}\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n')
        raw=echo.replace(b'\n',b'\r\r\n')+frame(value).replace(b'\n',b'\r\n')
        parsed=h._parse(raw,echo);self.assertEqual(value,parsed)
        result=h._caps_result(parsed);self.assertFalse(result['pass']);self.assertIsNone(result['status'])
        self.assertNotIn('traceback',repr(result));self.assertNotIn('SECRET_',repr(result))
        for bad in (raw+b'Traceback (most recent call last):\n',raw.replace(b"stage='modules'",b"stage='SECRET'",1),
            raw[len(echo)//2:],raw+b'MTA_REMOTE_OK\n'):
            with self.assertRaises((ValueError,SyntaxError)):h._parse(bad,echo)

    def test_phy_failure_traceback_private_raw_not_public_or_zip(self):
        FakeAdb.before=baseline(False);FakeAdb.after=baseline(False);FakeAdb.caps=phy_failure()
        report,out,archive=self.run_fake()
        self.assertFalse(report['pass']);self.assertTrue(report['limited_baseline_equal']);self.assertFalse(report['caps_read_invoked'])
        self.assertTrue(report['caps_read_requested']);self.assertNotIn('error_class',report)
        self.assertEqual({'stage':'phy','class':'value_error','errno':0},report['caps']['failure'])
        raw=(out/'private-raw'/'02-fixed-client-caps.stdout.raw').read_bytes()
        self.assertIn(b'SECRET_TRACEBACK',raw)
        for name in ('result.json','README.txt'):
            text=(out/name).read_text();self.assertNotIn('SECRET_',text);self.assertNotIn('Traceback (most recent call last):',text)
        with zipfile.ZipFile(archive) as bundle:
            self.assertEqual(['result.json','README.txt'],bundle.namelist())
            for name in bundle.namelist():self.assertNotIn(b'SECRET_TRACEBACK',bundle.read(name))

    def test_private_traceback_schema_required_and_utf8_byte_bound(self):
        for trace in (None,'','x'*h.MAX_TRACEBACK,'é'*(h.MAX_TRACEBACK//2)):
            value=phy_failure(trace);self.assertFalse(h._caps_result(value)['pass'])
        class TextSubclass(str):pass
        for trace in (True,0,b'trace',[],{},TextSubclass('secret'),'x'*(h.MAX_TRACEBACK+1),
            'é'*(h.MAX_TRACEBACK//2+1),'\ud800'):
            with self.assertRaises(ValueError):h._caps_result(phy_failure(trace))
        value=phy_failure();del value['private']['traceback']
        with self.assertRaises(ValueError):h._caps_result(value)
        value=phy_failure();value['private']['traceback_extra']='SECRET'
        with self.assertRaises(ValueError):h._caps_result(value)

    def test_transport_line_and_bytes_bounded_shell_fixed(self):
        _,sources=h.source_check()
        for source in sources:
            command,data,echo=h._transport(source)
            self.assertLessEqual(max(map(len,source.splitlines())),2048)
            self.assertNotRegex(command,r'\b(?:chmod|chown|mount|kill|iw|wpa_cli|ip)\b')
            if data is None:self.assertLessEqual(len(command),3500)
            else:self.assertEqual(data,echo);self.assertLessEqual(len(data),h.MAX_SOURCE)
        with self.assertRaises(ValueError):h._transport('x'*(h.MAX_SOURCE+1))

    def test_fake_success_is_readonly_limited_and_raw_private_zip_pair(self):
        report,out,archive=self.run_fake()
        self.assertTrue(report['pass']);self.assertTrue(report['caps_read_invoked'])
        self.assertEqual(3,len(FakeAdb.instances[0].calls));self.assertEqual('NOT_EVALUATED',report['all_ipv4_tables_rules'])
        self.assertEqual('NOT_EVALUATED',report['p2p_restoration']);self.assertFalse(report['selector_raw_captured'])
        for field in ('rf_operations','device_configuration_writes','receive_available','send_available'):self.assertIs(report[field],False)
        public=(out/'result.json').read_text()
        for secret in ('SECRET_', '02:11:', '12345678-1234', 'wlan0', '/usr/bin/', 'decoded', 'datagrams'):
            self.assertNotIn(secret,public)
        self.assertIn(b'SECRET_DATAGRAM',(out/'private-raw'/'02-fixed-client-caps.stdout.raw').read_bytes())
        self.assertEqual('0',(out/'private-raw'/'02-fixed-client-caps.remote-exit').read_text())
        with zipfile.ZipFile(archive) as bundle:self.assertEqual(['result.json','README.txt'],bundle.namelist())

    def test_missing_station_same_does_not_claim_restoration(self):
        FakeAdb.before=baseline(False);FakeAdb.after=baseline(False)
        report,_,_=self.run_fake();self.assertTrue(report['pass'])
        self.assertFalse(report['station_present_before']);self.assertEqual('NOT_EVALUATED',report['p2p_restoration'])

    def test_before_pin_fail_does_not_request_caps_but_after_independent(self):
        FakeAdb.before['hashes']['/usr/bin/Z03']='f'*64
        report,_,_=self.run_fake();self.assertFalse(report['pass']);self.assertFalse(report['caps_read_requested'])
        self.assertEqual(2,len(FakeAdb.instances[0].calls));self.assertTrue(report['after_stock_verified'])

    def test_changed_actor_task_or_interface_prevents_pass(self):
        FakeAdb.after['actors'][0]['tasks']=((11,100),(14,101))
        report,_,_=self.run_fake();self.assertFalse(report['pass']);self.assertFalse(report['limited_baseline_equal'])

    def test_unknown_close_retains_failure_no_false_success(self):
        FakeAdb.caps['status'].update(socket_closed=False,read_success=False,resource_pending=True,reason='socket_close_unverified')
        FakeAdb.caps['failure']={'stage':'read','class':'value_error','errno':0}
        report,_,_=self.run_fake();self.assertFalse(report['pass']);self.assertTrue(report['limited_baseline_equal'])

    def test_host_exit_failure_keeps_raw_and_remote_exit_separate(self):
        FakeAdb.fail_label='fixed-client-caps'
        report,out,_=self.run_fake();self.assertFalse(report['pass']);self.assertEqual('NOT_RECORDED',report['caps_read_invoked'])
        self.assertEqual('9',(out/'private-raw'/'02-fixed-client-caps.host-exit').read_text())
        self.assertEqual('0',(out/'private-raw'/'02-fixed-client-caps.remote-exit').read_text())
        self.assertNotIn('SECRET_HOST_ERROR',json.dumps(report))

    def test_public_schema_bool_count_unknown_reason_and_types_reject(self):
        changes=(lambda v:v['status'].update(socket_closed=1),lambda v:v['status'].update(reason='SECRET_REASON'),
            lambda v:v['caps'].update(phy_count=True),lambda v:v['caps'].update(iftypes=[True,8]),
            lambda v:v['caps'].update(limit_iftypes=[12]),lambda v:v['caps'].update(bi_min_gcd_present_count=2),
            lambda v:v['private'].update(requests=()),lambda v:v['status'].update(message_count=0))
        for change in changes:
            value=caps_result();change(value)
            with self.assertRaises(ValueError):h._caps_result(value)

    def test_baseline_strict_task_flags_and_stock_shapes(self):
        changes=(lambda v:v['actors'][0].update(pid=True),lambda v:v['actors'][0].update(tasks=((11,100),(11,101))),
            lambda v:v.update(boot=b'SECRET'),lambda v:v.update(actors=[]),lambda v:v.update(route4='text'),
            lambda v:v['hashes'].update({'/usr/bin/Z03':'x'*64}))
        for change in changes:
            value=baseline();change(value)
            with self.assertRaises(ValueError):h._baseline(value)

    def test_original_selector_exact_single_p011_not_default_emulator(self):
        good=b'emulator device product:sdk model:Android transport_id:1\nP011 device product:sprdtrum model:sprdisk transport_id:2\n'
        for raw,expected in ((good,'2'),(good+good,None),(b'emulator device product:sdk model:Android transport_id:1\n',None),(good.replace(b' device ',b' unauthorized '),None)):
            with patch.object(probe.subprocess,'run',return_value=subprocess.CompletedProcess([],0,raw,b'')):
                if expected:self.assertEqual(expected,probe.select_target())
                else:
                    with self.assertRaises(RuntimeError):probe.select_target()


if __name__=='__main__':unittest.main()
