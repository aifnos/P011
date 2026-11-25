"""Eight new SOURCE/Fake tests only; never ADB, actual proc, RF or cleanup."""
import ast
import base64
import builtins
import contextlib
import copy
import errno
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import types
import unittest
from unittest import mock

import test_client_init_tmp_alias_v11_host as v11
import test_client_proc as proc_fixture

BASE = Path(__file__).absolute().parents[1]
spec = importlib.util.spec_from_file_location('retained_v12_new_host', str(BASE / 'host/client_retained_stage_v12_readonly.py'))
driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)


class ReadonlyOS(v11.PathOS):
    O_NONBLOCK, SEEK_SET, O_TRUNC, O_WRONLY = 2048, 0, 512, 1

    def __init__(self, plan, definitions, close_error=False):
        super().__init__(close_error=close_error)
        self.plan = plan; self.mutate_manifest = False; self.manifest_seek_count = 0
        self.run = '/var/volatile/tmp/p011-mta-client-rfinit/client-' + plan['token']
        for path in ('/var/volatile/tmp/p011-mta-client-rfinit', self.run, self.run+'/runtime', self.run+'/native'):
            self.rows[path] = [stat.S_IFDIR|0o700, b'', len(self.rows)+1]
        env = driver.literals(driver.read_pinned(driver.REFERENCE/'target-source.py', driver.SOURCE_SHA))
        for name, pin, code in env['ENCODED']:
            self.put('runtime/'+name+'.py', base64.b64decode(code), 0o400)
        self.put('native/mta-wpa-supplicant', base64.b64decode(env['WPA_ENCODED']), 0o500)
        self.put('candidate.json', base64.b64decode(plan['candidate_encoded']), 0o400)
        provider = dict(plan['provider']); provider['python_sha'] = '1'*64
        self.put('deployment.json', __import__('json').dumps({'version':1,'provider':provider,
            'sources':plan['pins']}, sort_keys=True).encode('utf-8'), 0o400)

    def put(self, name, raw, mode):
        self.rows[self.run+'/'+name] = [stat.S_IFREG|mode, raw, len(self.rows)+1]

    def metadata(self, path):
        value = super().metadata(path); value.st_mtime_ns = 1; value.st_ctime_ns = 1
        return value

    def open(self, path, flags, mode=0, dir_fd=None):
        if flags & (os.O_CREAT|os.O_TRUNC|os.O_WRONLY|os.O_RDWR):
            raise AssertionError('readonly may not create or write')
        return super().open(path, flags, mode, dir_fd)

    def lseek(self, fd, offset, whence):
        if self.fds[fd][0] == self.run+'/candidate.json':
            self.manifest_seek_count += 1
            if self.mutate_manifest and self.manifest_seek_count == 2:
                self.rows[self.run+'/candidate.json'][1] += b' '
        return super().lseek(fd, offset, whence)

    def forbidden(self, *args, **kwargs): raise AssertionError('readonly mutation forbidden')
    mkdir = write = fchmod = fsync = forbidden


def pure_modules(definitions, loader):
    namespace = {'PINS': tuple((n,p) for n,p,e in definitions), 'ENCODED': definitions}
    exec(loader, namespace)
    return namespace['modules']


def run_target(plan, definitions, loader, filesystem=None, proc_factory=None, clock=None):
    modules = pure_modules(definitions, loader)
    fs = filesystem or ReadonlyOS(plan, definitions)
    if proc_factory:
        modules['mta_client_proc'].ProcReader = proc_factory(modules)
    else:
        modules['mta_client_proc'].ProcReader = mock.Mock(side_effect=AssertionError('unbound recorded actor may not read proc'))
    namespace = {'PLAN':copy.deepcopy(plan),'modules':modules,'base64':base64,
        'PINS':tuple((n,p) for n,p,e in definitions),'ORIGINAL_SOURCE_SHA':driver.SOURCE_SHA,
        'ORIGINAL_RECEIPT_SHA':driver.RECEIPT_SHA}
    output = io.StringIO()
    with contextlib.ExitStack() as stack:
        for name in ('O_RDONLY','O_DIRECTORY','O_NOFOLLOW','O_CLOEXEC','O_NONBLOCK','O_CREAT','O_TRUNC','O_WRONLY','O_RDWR','SEEK_SET'):
            stack.enter_context(mock.patch.object(os,name,getattr(fs,name),create=True))
        for name in ('stat','fstat','readlink','open','read','lseek','close'):
            stack.enter_context(mock.patch.object(os, name, getattr(fs,name)))
        for name in ('mkdir','write','chmod','unlink','rename','kill','waitpid'):
            stack.enter_context(mock.patch.object(os,name,side_effect=AssertionError('actual/mutation forbidden')))
        stack.enter_context(mock.patch('socket.socket',side_effect=AssertionError('network forbidden')))
        stack.enter_context(mock.patch.object(subprocess,'Popen',side_effect=AssertionError('child forbidden')))
        stack.enter_context(mock.patch('time.monotonic',clock or (lambda:100.0)))
        stack.enter_context(contextlib.redirect_stdout(output))
        exec(compile(driver.TARGET,'<new-readonly-target-over-FakeOS>','exec'),namespace)
    lines=output.getvalue().splitlines()
    if len(lines)!=1 or not lines[0].startswith('RESULT='):raise AssertionError('one receipt')
    return ast.literal_eval(lines[0][7:]),fs,namespace


class RetainedStageV12Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan,cls.definitions=driver.reference()
        cls.loader,cls.transport=driver.infrastructure()

    def test_actual_six_definition_graph_is_pure_and_old_twenty_are_data(self):
        with mock.patch.object(os,'open',side_effect=AssertionError('default IO forbidden')), \
                mock.patch('socket.socket',side_effect=AssertionError('socket forbidden')), \
                mock.patch.object(subprocess,'Popen',side_effect=AssertionError('child forbidden')):
            modules=pure_modules(self.definitions,self.loader)
        self.assertEqual(tuple(modules),driver.DEFINITIONS)
        self.assertEqual(len(self.plan['pins']),20);self.assertEqual(len(self.plan['files']),21)
        self.assertEqual(modules['mta_client_proc'].owner,modules['mta_p2p_client_init'])
        self.assertEqual(modules['mta_client_journal_codec'].core,modules['mta_p2p_client_init'])
        self.assertNotIn('mta_client_executor',modules);self.assertNotIn('mta_client_store',modules)

    def test_all_current_retained_files_and_absent_markers_original_once_close(self):
        receipt,fs,namespace=run_target(self.plan,self.definitions,self.loader)
        public=driver.validate_public(receipt['public'])
        self.assertTrue(public['manifest_match'],receipt['private']['errors']);self.assertTrue(public['retained_files_match'])
        self.assertFalse(public['resource_pending']);self.assertTrue(public['fixed_alias_verified'])
        self.assertEqual(public['journal_state'],'ABSENT');self.assertEqual(public['recorded_actor_count'],0)
        self.assertFalse(public['recorded_actors_known_absent']);self.assertFalse(public['restoration_verified'])
        self.assertEqual(len(fs.close_calls),len(set(fs.close_calls)))
        self.assertTrue(all(r['closed']or r['no_fd'] for r in receipt['private']['original_inventory']))
        self.assertEqual(fs.manifest_seek_count,2)
        namespace['modules']['mta_client_proc'].ProcReader.assert_not_called()

    def test_manifest_second_read_changed_and_one_source_bad_keep_other_facts(self):
        fs=ReadonlyOS(self.plan,self.definitions);fs.mutate_manifest=True
        fs.rows[fs.run+'/runtime/mta_client_caps.py'][1]=b'wrong preserved bytes'
        receipt,fs,namespace=run_target(self.plan,self.definitions,self.loader,fs)
        self.assertFalse(receipt['public']['manifest_match']);self.assertFalse(receipt['public']['retained_files_match'])
        facts=receipt['private']['facts']
        self.assertEqual(facts['runtime/mta_client_caps.py']['state'],'MISMATCH')
        self.assertEqual(facts['native/mta-wpa-supplicant']['state'],'MATCH')
        self.assertEqual(facts['launch_controller']['state'],'ABSENT')
        self.assertFalse(receipt['public']['resource_pending'])
        namespace['modules']['mta_client_proc'].ProcReader.assert_not_called()

    def test_bound_sidecar_real_proc_reader_two_pass_absence_and_invalid_binding_no_read(self):
        modules=pure_modules(self.definitions,self.loader);core=modules['mta_p2p_client_init'];json=modules['p011_json']
        cmd=b'/usr/bin/python3.5\0retained-Fake-only\0';sha=hashlib.sha256(cmd).hexdigest()
        actor={'pid':42,'start':100,'exe':'/usr/bin/python3.5','argv_sha':sha,'tasks':[[42,100,'S']]}
        parent=dict(actor,pid=99,tasks=[[99,100,'S']])
        target={'exe':actor['exe'],'argv_sha':sha,'binary_sha':'1'*64}
        ticket={'token':'2'*32,'role':'watchdog','boot':self.plan['boot'],'exe':actor['exe'],'argv_sha':sha}
        tree={'version':1,'kind':'direct_child_launch_registration','stage':'post_exec_durable',
            'identity':list(core.Identity(driver.CANDIDATE_SHA).key()),'run':'client-'+self.plan['token'],
            'role':'watchdog','deadline':200.0,'boot':self.plan['boot'],'target_ticket':ticket,
            'target':target,'parent':parent,'preexec':actor,'postexec':actor}
        fs=ReadonlyOS(self.plan,self.definitions);fs.put('launch-watchdog.json',json.dumps(tree,sort_keys=True).encode(),0o600)
        readers=[]
        def factory(current):
            actual=current['mta_client_proc'].ProcReader
            def construct(timeout):
                procfs=proc_fixture.FakeFs();procfs.remove_actor()
                procfs.files[proc_fixture.BOOT_PATH]=self.plan['boot'].encode()+b'\n'
                reader=actual(timeout=timeout,_fs=procfs,_clock=lambda:100.0);readers.append(reader);return reader
            return construct
        receipt,_,_=run_target(self.plan,self.definitions,self.loader,fs,factory)
        self.assertEqual(receipt['public']['recorded_actor_count'],1,receipt['private']['errors'])
        self.assertTrue(receipt['public']['recorded_actors_known_absent']);self.assertEqual(len(readers),1)
        observations=receipt['private']['actor_observations'][0]['observations']
        self.assertEqual(observations[0]['passes'],2);self.assertEqual(observations[0]['kind'],'absence')
        self.assertEqual(receipt['private']['reader_owner_count'],1)
        self.assertTrue(all(row['fresh_ebadf'] for row in receipt['private']['proc_inventory'][0]['original_fds']))
        # Actual Reader returns unknown on first permission error; a fresh Reader
        # may independently establish LIVE, never turn the missing pass absent.
        live_readers=[]
        def live_factory(current):
            actual=current['mta_client_proc'].ProcReader
            def construct(timeout):
                procfs=proc_fixture.FakeFs(cmd=cmd)
                procfs.files[proc_fixture.BOOT_PATH]=self.plan['boot'].encode()+b'\n'
                procfs.links['/proc/42/exe']='/usr/bin/python3.5'
                if not live_readers:procfs.fail[('open','/proc/42/stat')]=OSError(errno.EACCES,'Fake first observation')
                reader=actual(timeout=timeout,_fs=procfs,_clock=lambda:100.0);live_readers.append(reader);return reader
            return construct
        live_fs=ReadonlyOS(self.plan,self.definitions);live_fs.put('launch-watchdog.json',json.dumps(tree,sort_keys=True).encode(),0o600)
        live,_,_=run_target(self.plan,self.definitions,self.loader,live_fs,live_factory)
        self.assertEqual(len(live_readers),2)
        self.assertEqual(live['private']['reader_owner_count'],2)
        self.assertEqual(live['private']['actor_observations'][0]['state'],'LIVE')
        self.assertEqual([r['kind'] for r in live['private']['actor_observations'][0]['observations']],['unknown','live_actor'])
        self.assertFalse(live['public']['recorded_actors_known_absent'])
        self.assertFalse(live['public']['resource_pending'])
        self.assertFalse(live['public']['readonly_complete'])
        # Real _observe can return unknown AFTER two complete reads. Preserve
        # that error even if another independent Reader establishes LIVE.
        two_pass_readers=[]
        def two_pass_factory(current):
            actual=current['mta_client_proc'].ProcReader
            def construct(timeout):
                procfs=proc_fixture.FakeFs(cmd=cmd)
                procfs.files[proc_fixture.BOOT_PATH]=self.plan['boot'].encode()+b'\n'
                procfs.links['/proc/42/exe']='/usr/bin/python3.5'
                if not two_pass_readers:
                    def hook(fs,operation,path,count):
                        if operation=='open' and path=='/proc/42/stat' and count>=3:
                            fs.files[path]=proc_fixture.stat_data(42,start=101)
                    procfs.hook=hook
                reader=actual(timeout=timeout,_fs=procfs,_clock=lambda:100.0);two_pass_readers.append(reader);return reader
            return construct
        two_fs=ReadonlyOS(self.plan,self.definitions);two_fs.put('launch-watchdog.json',json.dumps(tree,sort_keys=True).encode(),0o600)
        two,_,_=run_target(self.plan,self.definitions,self.loader,two_fs,two_pass_factory)
        self.assertEqual(len(two_pass_readers),2)
        observed=two['private']['actor_observations'][0]
        self.assertEqual(observed['state'],'LIVE');self.assertFalse(observed['read_complete'])
        self.assertEqual([(o['kind'],o['passes']) for o in observed['observations']],[('unknown',2),('live_actor',2)])
        self.assertEqual(observed['observations'][0]['reason'],'observation_changed')
        self.assertFalse(two['public']['readonly_complete']);self.assertFalse(two['public']['resource_pending'])
        self.assertTrue(all(row['closed'] for row in two['private']['proc_inventory']))
        self.assertIn({'label':'launch_watchdog','kind':'ActorObservation','code':'actor_observation_incomplete'},two['private']['errors'])
        tree['run']='client-'+'f'*32
        fs=ReadonlyOS(self.plan,self.definitions);fs.put('launch-watchdog.json',json.dumps(tree,sort_keys=True).encode(),0o600)
        invalid,_,ns=run_target(self.plan,self.definitions,self.loader,fs)
        self.assertEqual(invalid['public']['recorded_actor_count'],0)
        self.assertIn('launch_watchdog_parse',invalid['private']['facts'])
        ns['modules']['mta_client_proc'].ProcReader.assert_not_called()

    def test_close_failure_retains_exact_original_pending_no_retry(self):
        receipt,fs,namespace=run_target(self.plan,self.definitions,self.loader,ReadonlyOS(self.plan,self.definitions,True))
        self.assertTrue(receipt['public']['resource_pending'])
        failed=[row for row in receipt['private']['original_inventory'] if row['label']=='volatile']
        self.assertEqual(len(failed),1);self.assertTrue(failed[0]['attempted']);self.assertFalse(failed[0]['closed'])
        namespace['owner'].close()
        self.assertEqual(len(fs.close_calls),len(set(fs.close_calls)))

    def test_invalid_alias_or_deadline_blocks_child_reads_without_cleanup(self):
        fs=ReadonlyOS(self.plan,self.definitions);fs.rows['/var/tmp'][1]=b'/wrong'
        receipt,fs,ns=run_target(self.plan,self.definitions,self.loader,fs)
        self.assertFalse(receipt['public']['fixed_alias_verified']);self.assertEqual(receipt['public']['journal_state'],'NOT_EVALUATED')
        self.assertEqual(receipt['public']['recorded_actor_count'],0);self.assertFalse(receipt['public']['resource_pending'])
        clock=iter([100.0,131.0]);receipt,fs,ns=run_target(self.plan,self.definitions,self.loader,clock=lambda:next(clock))
        self.assertFalse(receipt['public']['readonly_complete']);self.assertFalse(receipt['public']['rf_requested'])
        self.assertEqual(receipt['private']['original_inventory'],())

    def test_py35_source_readonly_call_graph_and_original_transport_no_kill(self):
        source=driver.build_source(self.plan,self.definitions,self.loader);tree=ast.parse(source,feature_version=(3,5))
        self.assertLess(max(len(line.encode()) for line in source.splitlines()),2049)
        inspected=ast.parse(driver.TARGET,feature_version=(3,5))
        names={n.func.attr for n in ast.walk(inspected) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
        self.assertFalse(names&{'mkdir','chmod','fchmod','write','fsync','unlink','rename','flock','kill','waitpid','acquire','restore','start','finish'})
        self.assertNotIn('Store',source);self.assertNotIn('ParentExecutor',source)
        process=v11.old.Process();helper=types.SimpleNamespace(ADB='FakeADB',select_target=lambda:'1')
        transport=self.transport(helper,Path('unused'),_popen=lambda *a,**k:process,_process_type=v11.old.Process,
            _fstat=lambda fd:(_ for _ in ()).throw(OSError(errno.EBADF,'Fake closed')))
        transport.select();transport.run('pass')
        self.assertEqual(process.calls[0][1],60);self.assertEqual(process.forbidden,[])

    def test_default_source_only_explicit_sha_and_strict_private_public_frames(self):
        checks={'source_check_pass':True,'driver_sha256':'a'*64}
        with mock.patch.object(driver,'source_check',return_value=(checks,'pass',None)), \
                mock.patch.object(driver,'execute',side_effect=AssertionError('default must not execute')), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(driver.main([]),0)
        with self.assertRaises(ValueError):driver.execute('b'*64,_check=lambda:(checks,'pass',None))
        receipt,_,_=run_target(self.plan,self.definitions,self.loader)
        echo=b"pass\nprint('MTA_REMOTE_OK')\n"
        raw={'stdout':echo+b'RESULT='+repr(receipt).encode()+b'\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n','stderr':b'','host_exit':0}
        parsed=driver.strict_receipt(raw,echo);driver.validate_public(parsed['public'])
        self.assertNotIn(self.plan['token'],repr(parsed['public']));self.assertNotIn(self.plan['boot'],repr(parsed['public']))
        raw['stdout']+=b'EXTRA\n'
        with self.assertRaises(ValueError):driver.strict_receipt(raw,echo)
        false=copy.deepcopy(receipt['public']);false['restoration_verified']=True
        with self.assertRaises(ValueError):driver.validate_public(false)


if __name__=='__main__':unittest.main()
