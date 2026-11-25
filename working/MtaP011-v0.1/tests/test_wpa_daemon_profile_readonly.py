"""Only new namespace compatibility Fake cases; no previous suite/actual OS."""
import ast
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest import mock
import zlib

BASE=Path(__file__).absolute().parents[1]
def load(name,path,pin=None):
    if pin is not None and hashlib.sha256(path.read_bytes()).hexdigest()!=pin:raise ValueError('fixture_pin')
    spec=importlib.util.spec_from_file_location(name,str(path));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
check=load('wpa_profile_check',BASE/'host/wpa_daemon_profile_readonly.py')
fixtures=load('wpa_identity_fixtures',BASE/'tests/test_wpa_daemon_identity_readonly.py','3b789e7c8707beca6b4ec0aa06c53947982bf3cb75e5c75d9f3c48c5563c5c5f')
CONFIG=b'CONFIG_IKCONFIG=y\n# CONFIG_NAMESPACES is not set\n'
def compress(raw):
    writer=zlib.compressobj(wbits=31);return writer.compress(raw)+writer.flush()


class ProfileChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks,cls.source,cls.legacy,project=check.source_check();cls.project=staticmethod(project);cls.ns={}
        exec(cls.source[:-len(cls.legacy.REMOTE_ENTRY)],cls.ns);cls.modules=cls.ns['modules']
    setUp=fixtures.Checks.setUp
    def make(self,reduced=True):
        fs=fixtures.FakeFs();names=['cgroup','mnt'] if reduced else ['mnt','net','pid','user']
        for root in ('/proc/41/ns','/proc/self/ns'):
            fs.dirs[root]=list(names)
            fs.links[root+'/cgroup']='cgroup:[123]'
        if reduced:
            for root in ('/proc/41/ns','/proc/self/ns'):
                for name in ('net','pid','user'):del fs.links[root+'/'+name]
            fs.data['/proc/config.gz']=compress(CONFIG)
        reader=fixtures.Reader(self.modules,fs)
        obj=self.ns['Collector'](self.modules['mta_client_proc'],self.modules['mta_p2p_client_init'],fs,fs.clock,reader)
        return obj,fs,reader
    def test_source_pins_exact_fragment_and_pure_ctor(self):
        obj,fs,reader=self.make();self.assertFalse(fs.opened);self.assertFalse(reader.calls)
        self.assertEqual(check.LEGACY_PIN,self.checks['legacy_checker_sha256'])
        self.assertEqual(self.legacy.PINS,tuple(self.ns['PINS']))
        for text in ('none','repeat repeat'):
            with self.assertRaises(ValueError):check._replace(text,'repeat','new')
        changed=self.legacy.REMOTE_CORE.replace("for name in ('mnt','net','pid','user'):","for name in ('mnt',):")
        with mock.patch.object(self.legacy,'REMOTE_CORE',changed),self.assertRaises(ValueError):check._adapt(self.legacy,Path(self.legacy.__file__).read_text(encoding='utf-8'))
    def test_reduced_profile_true_complete_not_four_equal_no_missing_inode(self):
        obj,fs,reader=self.make();value=obj.collect();public=self.project(value)
        self.assertTrue(public['pass_value'],value['failure']);self.assertTrue(public['profile_complete'])
        self.assertFalse(public['namespaces_equal']);self.assertEqual(2,public['namespace_count'])
        self.assertEqual('namespaces_disabled_cgroup_mnt',public['namespace_profile'])
        for key in ('identity_before','identity_after'):
            identity=value['private'][key];self.assertEqual(('cgroup','mnt'),tuple(name for name,pair in identity['namespaces']))
            self.assertTrue(all(type(link) is str for name,pair in identity['namespaces'] for link in pair))
            self.assertEqual(hashlib.sha256(CONFIG).hexdigest(),identity['namespace_profile']['config_sha256'])
        self.assertFalse(fs.live);self.assertEqual(2,len(reader.calls))
        self.assertEqual(2,len([row for row in value['private']['reads'] if row[0]=='/proc/config.gz']))
    def test_full_four_profile_preserves_original_truth(self):
        obj,fs,reader=self.make(False);value=obj.collect();public=self.project(value)
        self.assertTrue(public['pass_value']);self.assertTrue(public['namespaces_equal']);self.assertTrue(public['profile_complete'])
        self.assertEqual('full4_present',public['namespace_profile']);self.assertEqual(4,public['namespace_count'])
        self.assertFalse(any(path=='/proc/config.gz' for path,flags in fs.opened))
    def test_full_profile_actual_extra_entries_all_checked(self):
        obj,fs,reader=self.make(False)
        for root in ('/proc/41/ns','/proc/self/ns'):
            fs.dirs[root].extend(['cgroup','pid_for_children']);fs.links[root+'/pid_for_children']='pid:[123]'
        value=obj.collect();self.assertTrue(self.project(value)['pass_value']);self.assertEqual(6,value['summary']['namespace_count'])
        fs.links['/proc/41/ns/cgroup']='cgroup:[124]';obj,other,unused=self.make(False)
        other.dirs['/proc/41/ns'].append('cgroup');other.dirs['/proc/self/ns'].append('cgroup');other.links['/proc/41/ns/cgroup']='cgroup:[124]'
        self.assertFalse(self.project(obj.collect())['pass_value'])
    def test_unproved_configuration_no_skip_or_child_symbol_inference(self):
        for raw in (b'CONFIG_IKCONFIG=y\n',b'CONFIG_NAMESPACES=y\n',b'CONFIG_NAMESPACES=n\n',CONFIG+b'CONFIG_NAMESPACES=y\n',CONFIG+CONFIG,CONFIG.replace(b'\n',b'\r\n')):
            obj,fs,reader=self.make();fs.data['/proc/config.gz']=compress(raw);value=obj.collect()
            if raw==CONFIG.replace(b'\n',b'\r\n'):
                self.assertTrue(self.project(value)['pass_value'])
            else:self.assertEqual('namespace_config',value['failure']['reason']);self.assertFalse(self.project(value)['pass_value'])
        obj,fs,reader=self.make();del fs.data['/proc/config.gz'];value=obj.collect()
        self.assertEqual(errno.ENOENT,value['failure']['errno']);self.assertFalse(self.project(value)['pass_value'])
    def test_config_decompression_eof_bounds_suffix_and_crc(self):
        valid=compress(CONFIG);parse=self.ns['namespace_config']
        self.assertEqual(hashlib.sha256(CONFIG).hexdigest(),parse(valid))
        damaged=bytearray(valid);damaged[-8]^=1
        for raw in (valid[:-1],valid+b'extra',valid+valid,bytes(damaged),b'x'*262145,compress(b'x'*1048577),compress(CONFIG+b'\0'),compress(CONFIG+b'\xff'),compress(CONFIG.rstrip(b'\n'))):
            with self.assertRaises(ValueError):parse(raw)
    def test_presence_different_missing_unknown_duplicate_and_many_fail(self):
        for mode in ('different','empty','mnt_only','unknown','duplicate','many'):
            obj,fs,reader=self.make()
            if mode=='different':fs.dirs['/proc/41/ns']=['mnt']
            else:
                names=[] if mode=='empty' else ['mnt'] if mode=='mnt_only' else ['cgroup','mnt','future'] if mode=='unknown' else ['cgroup','mnt','mnt'] if mode=='duplicate' else ['mnt']*9
                fs.dirs['/proc/41/ns']=list(names);fs.dirs['/proc/self/ns']=list(names)
            value=obj.collect();self.assertFalse(self.project(value)['pass_value']);self.assertFalse(value['summary']['namespaces_equal'])
    def test_listed_link_missing_invalid_or_unequal_is_failure(self):
        for mode in ('missing','format','unequal'):
            obj,fs,reader=self.make();original=fs.readlink
            if mode=='missing':
                def missing(path):
                    if path=='/proc/41/ns/cgroup':raise OSError(errno.ENOENT,'PRIVATE_LINK_GONE')
                    return original(path)
                fs.readlink=missing
            else:fs.links['/proc/41/ns/cgroup']='cgroup:[124]' if mode=='unequal' else 'cgroup:[0]'
            value=obj.collect();self.assertFalse(self.project(value)['pass_value']);self.assertFalse(value['summary']['profile_complete'])
            self.assertTrue(value['summary']['files_closed']);self.assertFalse(value['summary']['resource_pending'])
    def test_namespace_directory_change_after_first_fails(self):
        obj,fs,reader=self.make();original=fs.listdir;counts={}
        def changed(path):
            counts[path]=counts.get(path,0)+1
            if path.endswith('/ns') and counts[path]>1:return ['mnt']
            return original(path)
        fs.listdir=changed;value=obj.collect();self.assertFalse(self.project(value)['pass_value'])
        self.assertTrue(value['private']['namespace_directories']);self.assertEqual('identity_after',value['failure']['stage'])
    def test_config_change_after_first_and_actor_change_fails(self):
        for mode in ('config','actor'):
            obj,fs,reader=self.make()
            if mode=='actor':reader.changed=True
            else:
                original=fs.open;seen=[0]
                def changed(path,flags):
                    if path=='/proc/config.gz':
                        seen[0]+=1
                        if seen[0]>1:fs.data[path]=compress(CONFIG+b'CONFIG_TEST=y\n')
                    return original(path,flags)
                fs.open=changed
            value=obj.collect();self.assertFalse(self.project(value)['pass_value'])
    def test_missing_wlan_and_multiple_daemon_keep_original_rejection(self):
        obj,fs,reader=self.make();fs.dirs['/sys/class/net']=['lo'];value=obj.collect();public=self.project(value)
        self.assertFalse(public['pass_value']);self.assertTrue(public['profile_complete']);self.assertTrue(public['wlan_observed']);self.assertEqual('wlan_absent',public['failure']['reason'])
        obj,fs,reader=self.make();fs.data['/proc/42/comm']=b'wpa_supplicant\n';value=obj.collect()
        self.assertFalse(self.project(value)['pass_value']);self.assertFalse(reader.calls);self.assertEqual('daemon_selection',value['failure']['reason'])
    def test_private_profile_config_and_hash_not_public(self):
        obj,fs,reader=self.make();value=obj.collect();public=json.dumps(self.project(value))
        for secret in ('/proc','PRIVATE','cgroup:[',hashlib.sha256(CONFIG).hexdigest(),value['private']['identity_before']['image_sha']):self.assertNotIn(secret,public)
    def test_projection_rejects_forged_profile_completion_and_missing_fields(self):
        obj,fs,reader=self.make();value=obj.collect()
        for mode in ('full_equal','count','kind','bool','missing','false_ready'):
            bad={'summary':dict(value['summary']),'failure':dict(value['failure']),'private':value['private']}
            if mode=='full_equal':bad['summary']['namespaces_equal']=True
            elif mode=='count':bad['summary']['namespace_count']=3
            elif mode=='kind':bad['summary']['namespace_profile']='PRIVATE_PROFILE'
            elif mode=='bool':bad['summary']['profile_complete']=1
            elif mode=='missing':del bad['summary']['profile_complete']
            else:bad['summary']['profile_complete']=False
            with self.assertRaises(ValueError):self.project(bad)
    def test_unknown_original_fd_sticky_not_closed_or_reused(self):
        obj,fs,reader=self.make();fs.close_error=True;value=obj.collect();public=self.project(value)
        self.assertFalse(public['pass_value']);self.assertTrue(public['resource_pending']);self.assertFalse(public['files_closed'])
        original=obj.files.refs[0];self.assertIs(original['fs'],fs);before=tuple(fs.closed)
        with self.assertRaises(ValueError):obj.files.read('/proc/config.gz',262144)
        obj.files.close(original);self.assertEqual(before,tuple(fs.closed))
    def test_no_device_default_cli_and_bad_self_pin(self):
        with mock.patch.object(check,'run_readonly') as run,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0,check.main([]));run.assert_not_called()
        with mock.patch.object(check,'source_check',return_value=(self.checks,self.source,self.legacy,self.project)),self.assertRaises(ValueError):check.run_readonly('0'*64)
        for args in (['--execute-readonly'],['--expected-checker-sha256','a'*64],['--namespace','net']):
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):check.main(args)
    def test_python35_ast_and_unchanged_legacy_global_source(self):
        ast.parse(self.source,feature_version=(3,5));ast.parse((BASE/'host/wpa_daemon_profile_readonly.py').read_text(encoding='utf-8'),feature_version=(3,5))
        original=(BASE/'host/wpa_daemon_identity_readonly.py').read_bytes();self.assertEqual(check.LEGACY_PIN,hashlib.sha256(original).hexdigest())
        self.assertNotIn('profile_complete',self.legacy.BOOLS);self.assertNotIn('namespace_count',self.legacy.COUNTS)
        tree=ast.parse(self.source);attrs={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
        self.assertFalse({'write','mkdir','unlink','socket','Popen','flock','chmod','chown','kill'}&attrs)
        self.assertFalse(any(isinstance(n,ast.Assert) for n in ast.walk(tree)))
    def link_fixture(self,links,original='/var/run/wpa_supplicant/wlan0',special=None):
        obj,fs,reader=self.make();fs.data['/proc/net/unix']=fixtures.unix(path=original.encode())
        old=fs.lstat;special=special or {};known={path:index+2000 for index,path in enumerate(sorted(links))}
        for path,target in links.items():fs.links[path]=target
        def metadata(path):
            if path in links or path in special:
                mode,uid,nlink=special.get(path,(stat.S_IFLNK|0o777,0,1))
                return SimpleNamespace(st_dev=2,st_ino=known.get(path,3000),st_mode=mode,st_uid=uid,st_gid=0,st_nlink=nlink,st_size=len(links.get(path,'')),st_mtime_ns=1,st_ctime_ns=1)
            return old(path)
        fs.lstat=metadata
        return obj,fs,reader
    def test_link_absolute_parent_actual_target_and_canonical_socket(self):
        obj,fs,reader=self.link_fixture({'/var/run':'/run'});value=obj.collect();public=self.project(value)
        self.assertTrue(public['pass_value'],value['failure']);self.assertFalse(fs.live)
        endpoint=value['private']['endpoint_before'];self.assertEqual('/var/run/wpa_supplicant/wlan0',endpoint['path'])
        self.assertEqual('/run/wpa_supplicant/wlan0',endpoint['chain'][-1][0]);self.assertEqual(777,endpoint['chain'][-1][1][1]);self.assertEqual(555,endpoint['row'][0])
        symbolic=[row for row in endpoint['chain'] if row[2] is not None]
        self.assertEqual('/run',symbolic[0][2]);self.assertEqual(0o777,symbolic[0][1][2]&0o777)
        self.assertEqual(value['private']['endpoint_before'],value['private']['endpoint_after'])
    def test_link_relative_and_dot_target_are_physical_parent_based(self):
        for target,final in (('../run','/run/wpa_supplicant/wlan0'),('./runtime/../runtime','/var/runtime/wpa_supplicant/wlan0'),('/real/path/../path','/real/path/wpa_supplicant/wlan0')):
            obj,fs,reader=self.link_fixture({'/var/run':target});value=obj.collect()
            self.assertTrue(self.project(value)['pass_value'],value['failure']);self.assertEqual(final,value['private']['endpoint_before']['chain'][-1][0])
    def test_link_does_not_guess_var_run_target(self):
        obj,fs,reader=self.link_fixture({'/var/run':'/custom/private'});value=obj.collect()
        self.assertTrue(self.project(value)['pass_value']);chain=value['private']['endpoint_before']['chain']
        self.assertEqual('/custom/private/wpa_supplicant/wlan0',chain[-1][0]);self.assertFalse(any(row[0]=='/run' for row in chain))
    def test_link_dotdot_after_intermediate_link_uses_actual_physical_stack(self):
        obj,fs,reader=self.link_fixture({'/var/run':'/jump/../right','/jump':'/physical/deep'});value=obj.collect()
        self.assertTrue(self.project(value)['pass_value'],value['failure'])
        chain=value['private']['endpoint_before']['chain'];self.assertEqual('/physical/right/wpa_supplicant/wlan0',chain[-1][0])
        self.assertTrue(any(row[0]=='/physical/deep' for row in chain));self.assertFalse(any(row[0]=='/right' for row in chain))
    def test_link_cycle_and_ninth_link_reject_but_eight_pass(self):
        obj,fs,reader=self.link_fixture({'/var/run':'/cycle','/cycle':'/var/run'});value=obj.collect()
        self.assertFalse(self.project(value)['pass_value']);self.assertEqual('endpoint_metadata',value['failure']['reason'])
        for count in (8,9):
            links={'/var/run':'/link0'}
            for index in range(count-1):links['/link'+str(index)]='/link'+str(index+1)
            obj,fs,reader=self.link_fixture(links);value=obj.collect()
            self.assertEqual(count==8,self.project(value)['pass_value'],value['failure'])
    def test_link_foreign_owner_and_writable_resolved_parent_or_socket_reject(self):
        for special in ({'/var/run':(stat.S_IFLNK|0o777,1,1)}, {'/resolved':(stat.S_IFDIR|0o777,0,1)}, {'/resolved/wpa_supplicant':(stat.S_IFDIR|0o775,0,1)}, {'/resolved/wpa_supplicant/wlan0':(stat.S_IFSOCK|0o666,0,1)}):
            obj,fs,reader=self.link_fixture({'/var/run':'/resolved'},special=special);value=obj.collect()
            self.assertFalse(self.project(value)['pass_value']);self.assertTrue(value['summary']['files_closed'])
    def test_link_metadata_changes_during_actual_readlink_reject(self):
        obj,fs,reader=self.link_fixture({'/var/run':'/resolved'});old=fs.lstat;calls=[0]
        def changed(path):
            value=old(path)
            if path=='/var/run':
                calls[0]+=1
                if calls[0]>1:value.st_ino+=1
            return value
        fs.lstat=changed;value=obj.collect();self.assertFalse(self.project(value)['pass_value'])
        self.assertEqual('identity_changed',value['failure']['reason']);self.assertIn('path_observations',value['private'])
    def test_link_target_changes_between_identity_passes_reject(self):
        obj,fs,reader=self.link_fixture({'/var/run':'/first'});old=fs.readlink;calls=[0]
        def changed(path):
            if path=='/var/run':
                calls[0]+=1
                if calls[0]>1:return '/second'
            return old(path)
        fs.readlink=changed;value=obj.collect();self.assertFalse(self.project(value)['pass_value'])
        self.assertEqual('identity_changed',value['failure']['reason']);self.assertEqual(2,len(value['private']['path_links']))
    def test_link_unknown_missing_target_and_normalization_bounds_fail(self):
        for mode in ('missing','nul','escape','too_many','too_long'):
            target='/resolved' if mode=='missing' else '/bad\0target' if mode=='nul' else '../../escape' if mode=='escape' else '/'+('/a'*65) if mode=='too_many' else '/'+('a'*4097)
            obj,fs,reader=self.link_fixture({'/var/run':target})
            if mode=='missing':
                old=fs.readlink
                def missing(path):
                    if path=='/var/run':raise OSError(errno.ENOENT,'PRIVATE_LINK_MISSING')
                    return old(path)
                fs.readlink=missing
            value=obj.collect();self.assertFalse(self.project(value)['pass_value']);self.assertTrue(value['summary']['files_closed']);self.assertFalse(value['summary']['resource_pending'])
    def test_link_evidence_private_and_source_version_fixed(self):
        obj,fs,reader=self.link_fixture({'/var/run':'/PRIVATE_TARGET'});value=obj.collect();public=json.dumps(self.project(value))
        self.assertNotIn('PRIVATE_TARGET',public);self.assertNotIn('/var/run',public);self.assertNotIn('path_links',public)
        self.assertEqual('wpa-profile-v2-owned-path-links',self.checks['source_version']);self.assertIn('path_links',value['private'])
    def test_link_final_target_trailing_slash_requires_directory(self):
        for target,physical in (('/real/socket/','/real/socket'),('/real/socket//','/real/socket'),('../socket/','/var/run/socket')):
            obj,fs,reader=self.link_fixture({'/var/run/wpa_supplicant/wlan0':target},special={physical:(stat.S_IFSOCK|0o660,0,1)})
            value=obj.collect();self.assertFalse(self.project(value)['pass_value'])
            self.assertEqual('endpoint_path',value['failure']['reason']);self.assertTrue(value['summary']['files_closed'])


if __name__=='__main__':unittest.main()
