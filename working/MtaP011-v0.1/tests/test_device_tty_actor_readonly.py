"""HOST fake-only target/dispatch checks; never ADB, proc, PTY or RF calls."""
import ast
import base64
import builtins
import contextlib
import copy
import errno
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock
import zipfile
import zlib

PROJECT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT/'host'))
import device_tty_actor_readonly as checker


def argv(count=32270):
    return [b'python3',b'-B',b'-c',b'import sys;exec(sys.stdin.buffer.read('+str(count).encode('ascii')+b'))',b'mta-prior-readonly']


def cmdline(args):return b'\0'.join(args)+b'\0'


def stat_bytes(start=100):return b'7 (HOST PRIVATE NAME) '+b' '.join([b'S']+[b'1']*18+[str(start).encode('ascii')])+b'\n'


class Environment:
    def __init__(self,first=None,second=None,tty=True,mode=10,termios=True):
        self.snapshots=[first if first is not None else {},second if second is not None else (first or {})]
        self.current=-1;self.tty=tty;self.mode=mode;self.termios=termios;self.clock=0
        self.opens=[];self.reads=[];self.closed=[];self.stat_faults={};self.cmd_faults={};self.second_stat={};self.second_cmd={};self.calls={}
        self.names=None;self.deadline=False;self.list_fault=False;self.tty_fault=False;self.mode_fault=False
    def listdir(self,path):
        if path!='/proc':raise AssertionError('HOST arbitrary directory')
        self.current+=1
        if self.list_fault:raise OSError(errno.EACCES,'HOST_SECRET')
        return self.names if self.names is not None else list(self.snapshots[self.current])+['self','uptime']
    def monotonic(self):
        self.clock+=1
        return self.clock*10 if self.deadline else self.clock*.001
    def isatty(self,fd):
        if fd!=0:raise AssertionError('HOST arbitrary FD')
        if self.tty_fault:raise OSError('HOST_SECRET_TTY')
        return self.tty
    def tcgetattr(self,fd):
        if fd!=0:raise AssertionError('HOST arbitrary FD')
        if self.mode_fault:raise OSError('HOST_SECRET_IOCTL')
        return [0,0,0,self.mode,0,0,[]]
    def open(self,path,mode):
        if mode!='rb' or not path.startswith('/proc/') or len(path.split('/'))!=4:
            raise AssertionError('HOST arbitrary read')
        unused,proc,pid,kind=path.split('/')
        if kind not in ('cmdline','stat') or not pid.isdigit():raise AssertionError('HOST arbitrary proc file')
        self.opens.append(path);key=(self.current,pid,kind);self.calls[key]=self.calls.get(key,0)+1
        fault=(self.cmd_faults if kind=='cmdline' else self.stat_faults).get(pid)
        if fault is not None:raise fault
        row=self.snapshots[self.current][pid]
        value=row if kind=='cmdline' else stat_bytes()
        if self.calls[key]>1:value=(self.second_cmd if kind=='cmdline' else self.second_stat).get(pid,value)
        environment=self
        class File:
            def __enter__(self):return self
            def read(self,count):environment.reads.append(count);return value[:count]
            def __exit__(self,*unused):environment.closed.append(path)
        return File()
    def execute(self):
        modules={'os':types.SimpleNamespace(listdir=self.listdir,isatty=self.isatty),
                 'time':types.SimpleNamespace(monotonic=self.monotonic,sleep=lambda seconds:None),
                 'termios':types.SimpleNamespace(tcgetattr=self.tcgetattr,ICANON=2,ECHO=8)}
        def importer(name,*unused,**kwargs):
            if name=='termios' and not self.termios:raise ImportError('HOST_SECRET_MODULE')
            if name not in modules:raise AssertionError('HOST forbidden import')
            return modules[name]
        namespace={'__builtins__':dict(vars(builtins),__import__=importer,open=self.open)}
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream):exec(checker.source(),namespace)
        lines=stream.getvalue().splitlines()
        if len(lines)!=1 or not lines[0].startswith('RESULT='):raise AssertionError('HOST fixed output')
        value=ast.literal_eval(lines[0][7:]);checker.validate_result(value)
        return value,stream.getvalue(),namespace


class ProgramTests(unittest.TestCase):
    def test_ast_short_compressed_no_stdin_and_bounded_program(self):
        with mock.patch.object(checker,'Adb',side_effect=AssertionError('HOST no ADB')):
            source=checker.source();tree=ast.parse(source,feature_version=(3,5));command=checker.compressed_command(source)
        self.assertLessEqual(len(source.encode('utf-8')),8192)
        self.assertLessEqual(max(len(line.encode('utf-8')) for line in source.splitlines()),2048)
        self.assertLess(len(command.encode('ascii')),3500);self.assertNotIn('exec(sys.stdin',command)
        payload=command.split("base64.b64decode('",1)[1].split("')",1)[0]
        self.assertEqual(zlib.decompress(base64.b64decode(payload)).decode('utf-8'),source)
        forbidden={'Popen','run','kill','terminate','signal','tcsetattr','system','chmod','unlink','remove','write','bind','connect','listen','sendto','mkdir'}
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):self.assertNotIn(node.func.attr,forbidden)
        self.assertIn('len(pids)>512',source);self.assertIn('limit+1',source);self.assertIn('races>32',source)

    def test_exact_five_args_read32270_and_other_counts_public_no_identities(self):
        rows={'7':cmdline(argv()),'8':cmdline(argv(100)),'9':cmdline([b'HOST_SECRET_EXE',b'mta-prior-readonly']),
              '10':cmdline([b'python3',b'HOST_SECRET_NO_MARKER'])}
        value,text,namespace=Environment(rows).execute()
        self.assertTrue(value['tty_mode_observed']);self.assertTrue(value['icanon']);self.assertTrue(value['echo'])
        self.assertTrue(value['snapshots_consistent'])
        for position in ('first','second'):
            self.assertEqual(value['exact_readonly_actors_'+position],1)
            self.assertEqual(value['other_read_count_actors_'+position],1)
            self.assertEqual(value['other_prior_marker_actors_'+position],1)
        self.assertNotIn('HOST_SECRET',text);self.assertNotIn('pid',text);self.assertNotIn('32270',text)
        self.assertTrue(namespace['first'][1]) # Identities stay in private target memory, never output.

    def test_malformed_same_marker_never_disappears_as_other_zero(self):
        malformed=[argv()+[b'extra'],[b'/usr/bin/python3']+argv()[1:],argv()[1:],
                   [b'python3',b'-B',b'-c',b'HOST_SECRET_CODE',b'mta-prior-readonly'],
                   [b'python3',b'-B',b'-c',b'import sys;exec(sys.stdin.buffer.read(032270))',b'mta-prior-readonly']]
        value,unused,namespace=Environment({str(index+1):cmdline(row) for index,row in enumerate(malformed)}).execute()
        self.assertEqual(value['exact_readonly_actors_first'],0);self.assertEqual(value['other_read_count_actors_first'],0)
        self.assertEqual(value['other_prior_marker_actors_first'],len(malformed))

    def test_changed_identity_same_counts_not_consistent(self):
        value,unused,namespace=Environment({'7':cmdline(argv())},{'8':cmdline(argv())}).execute()
        self.assertEqual(value['exact_readonly_actors_first'],value['exact_readonly_actors_second'])
        self.assertFalse(value['snapshots_consistent'])

    def test_starttime_or_cmdline_changed_during_one_snapshot_fails_complete(self):
        for kind in ('stat','cmdline'):
            env=Environment({'7':cmdline(argv())})
            if kind=='stat':env.second_stat['7']=stat_bytes(999)
            else:env.second_cmd['7']=cmdline(argv(100))
            value,unused,namespace=env.execute();self.assertFalse(value['snapshot_first_complete']);self.assertFalse(value['snapshots_consistent'])

    def test_proc_permission_or_stat_read_failure_is_incomplete_no_error_text(self):
        for kind in ('cmdline','stat'):
            env=Environment({'7':cmdline(argv())})
            (env.cmd_faults if kind=='cmdline' else env.stat_faults)['7']=OSError(errno.EACCES,'HOST_SECRET_PROC')
            value,text,namespace=env.execute()
            self.assertFalse(value['snapshot_first_complete']);self.assertFalse(value['snapshot_second_complete'])
            self.assertFalse(value['snapshots_consistent']);self.assertNotIn('HOST_SECRET',text)

    def test_transient_enoent_esrch_bounded_and_never_universal_absence(self):
        for number in (errno.ENOENT,errno.ESRCH):
            env=Environment({'7':cmdline(argv())});env.cmd_faults['7']=OSError(number,'HOST_SECRET_GONE')
            value,unused,namespace=env.execute();self.assertTrue(value['snapshot_first_complete']);self.assertEqual(value['exact_readonly_actors_first'],0)
        env=Environment({str(index):cmdline(argv()) for index in range(33)})
        env.cmd_faults={pid:OSError(errno.ENOENT,'HOST_SECRET_GONE') for pid in env.snapshots[0]}
        value,unused,namespace=env.execute();self.assertFalse(value['snapshot_first_complete'])

    def test_proc_count_list_deadline_and_read_bounds_fail_closed(self):
        cases=[]
        env=Environment();env.names=[str(index) for index in range(513)];cases.append(env)
        env=Environment();env.names=['self']*4097;cases.append(env)
        env=Environment({'7':cmdline(argv())});env.deadline=True;cases.append(env)
        env=Environment();env.list_fault=True;cases.append(env)
        env=Environment({'7':b'x'*4097});cases.append(env)
        env=Environment({'7':cmdline(argv())[:-1]});cases.append(env)
        for env in cases:
            value,text,namespace=env.execute();self.assertFalse(value['snapshot_first_complete']);self.assertFalse(value['snapshots_consistent'])
            self.assertTrue(all(count<=4097 for count in env.reads));self.assertEqual(env.opens,env.closed)

    def test_termios_missing_ioctl_failed_not_tty_and_flags_are_distinct(self):
        value,unused,namespace=Environment(termios=False).execute();self.assertIsNone(value['tty_mode_observed'])
        env=Environment();env.mode_fault=True;value,unused,namespace=env.execute();self.assertIs(value['tty_mode_observed'],False)
        value,unused,namespace=Environment(tty=False).execute();self.assertIs(value['stdin_is_tty'],False);self.assertIs(value['tty_mode_observed'],False)
        env=Environment();env.tty_fault=True;value,unused,namespace=env.execute();self.assertIsNone(value['stdin_is_tty'])
        value,unused,namespace=Environment(mode=0).execute();self.assertTrue(value['tty_mode_observed']);self.assertIs(value['icanon'],False);self.assertIs(value['echo'],False)

    def test_strict_schema_rejects_extra_identity_truthy_or_inconsistent_counts(self):
        baseline=Environment().execute()[0]
        mutations=[('icanon',1),('stdin_is_tty','true'),('exact_readonly_actors_first',True),('other_read_count_actors_second',513),
                   ('snapshot_first_complete',1),('pid',7),('echo',None),('stdin_is_tty',False)]
        for key,bad in mutations:
            value=dict(baseline);value[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):checker.validate_result(value)
        value=dict(baseline);value['exact_readonly_actors_second']=1
        with self.assertRaises(ValueError):checker.validate_result(value)
        value=dict(baseline);value['snapshot_first_complete']=False
        with self.assertRaises(ValueError):checker.validate_result(value)


class DispatchTests(unittest.TestCase):
    def fake_run(self,value,failure=False):
        calls=[]
        class FakeAdb:
            def __init__(self,directory):calls.append(('construct',Path(directory).name))
            def python(self,label,program,timeout):
                calls.append((label,program,timeout))
                if failure:raise RuntimeError('HOST_SECRET_RAW_PATH_PID')
                return copy.deepcopy(value)
        with tempfile.TemporaryDirectory() as directory,mock.patch.object(checker,'Adb',FakeAdb):
            out=Path(directory)/'new-observation';report,path,archive=checker.run_check(out)
            with zipfile.ZipFile(archive) as bundle:
                self.assertEqual(set(bundle.namelist()),{'result.json','README.txt'})
                self.assertIsNone(bundle.testzip());contents=bundle.read('result.json').decode('utf-8')
            self.assertNotIn('HOST_SECRET',contents);self.assertNotIn('private-raw',contents)
            self.assertFalse(report['radio_operations']);self.assertFalse(report['signals_sent']);self.assertFalse(report['cleanup_invoked'])
            self.assertEqual(report['historical_tty_mode'],'NOT_PROVEN');self.assertEqual(report['all_resources_absent'],'NOT_PROVEN')
            return report,calls
    def test_one_fixed_short_invocation_and_two_public_only_snapshots(self):
        report,calls=self.fake_run(Environment().execute()[0])
        self.assertTrue(report['check_complete']);self.assertTrue(report['pass']);self.assertTrue(report['observed_prior_marker_actors_zero'])
        self.assertEqual(len(calls),2);self.assertEqual(calls[1][0],'current-tty-exact-prior-actor-readonly')
        self.assertEqual(calls[1][1],checker.source());self.assertEqual(calls[1][2],15)
    def test_actor_present_collection_pass_does_not_admit_zero_or_cleanup(self):
        report,calls=self.fake_run(Environment({'7':cmdline(argv())}).execute()[0])
        self.assertTrue(report['check_complete']);self.assertTrue(report['pass']);self.assertFalse(report['observed_prior_marker_actors_zero'])
    def test_incomplete_or_host_failure_not_pass_and_exception_not_public(self):
        value=Environment().execute()[0];value.update(snapshot_first_complete=False,snapshots_consistent=False)
        report,calls=self.fake_run(value);self.assertFalse(report['check_complete']);self.assertFalse(report['pass'])
        report,calls=self.fake_run(value,failure=True);self.assertTrue(report['host_or_parse_error']);self.assertFalse(report['observed_prior_marker_actors_zero'])
    def test_source_budget_failure_precedes_adb_or_any_output(self):
        with tempfile.TemporaryDirectory() as directory,mock.patch.object(checker,'SOURCE','x'*8193),mock.patch.object(checker,'Adb',side_effect=AssertionError('HOST no ADB')):
            out=Path(directory)/'uncreated'
            with self.assertRaises(ValueError):checker.run_check(out)
            self.assertFalse(out.exists())


if __name__=='__main__':unittest.main()
