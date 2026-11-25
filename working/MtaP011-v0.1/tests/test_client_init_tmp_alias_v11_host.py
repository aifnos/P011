"""v11 new TARGET over registered Fake directory FDs; never ADB/RF/OS writes."""
import ast
import base64
import contextlib
import errno
import hashlib
import importlib.util
import io
from pathlib import Path
import stat
import types
import unittest
from unittest import mock

import test_client_init_p011_host as old

BASE = Path(__file__).absolute().parents[1]
HOST = BASE / 'host/client_init_tmp_alias_v11_p011.py'
COMMON = BASE / 'candidate/client-tmp-alias-v11/runtime/mta_client_tmp_alias.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


driver = load('isolated_client_tmp_alias_v11_host', HOST)
alias = load('isolated_client_tmp_alias_v11_common', COMMON)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def clone(function, **bindings):
    values = dict(function.__globals__); values.update(bindings)
    return types.FunctionType(function.__code__, values, function.__name__,
        function.__defaults__, function.__closure__)


fixture_source = clone(old.fixture_source, driver=driver)
target_run = clone(old.TargetFixture.run, driver=driver, fixture_source=fixture_source)


class PathOS(old.FakeOS):
    """Fixed alias tree and real original-FD semantics, in memory only."""
    def __init__(self, pending=False, old_stage=False, broken_alias=False,
                 denied_prefix=False, close_error=False):
        old.FakeOS.__init__(self, pending)
        for path, mode, data in (
                ('/', stat.S_IFDIR | 0o755, b''),
                ('/tmp', stat.S_IFLNK | 0o777, b'/var/tmp'),
                ('/var', stat.S_IFDIR | 0o755, b''),
                ('/var/tmp', stat.S_IFLNK | 0o777, b'/var/volatile/tmp'),
                ('/var/volatile', stat.S_IFDIR | 0o1777, b''),
                ('/var/volatile/tmp', stat.S_IFDIR | 0o1777, b'')):
            self.rows[path] = [mode, data, len(self.rows) + 1]
        if broken_alias: self.rows['/var/tmp'][1] = b'/not/the/fixed/plan'
        if denied_prefix: self.rows['/var'][0] = stat.S_IFDIR | 0o777
        if old_stage:
            self.rows['/var/volatile/tmp/p011-mta-client-rfinit'] = [stat.S_IFDIR | 0o700, b'', len(self.rows)+1]
            self.rows['/var/volatile/tmp/p011-mta-client-rfinit/OLD'] = [stat.S_IFREG | 0o400, b'KEEP', len(self.rows)+1]
        self.close_error = close_error; self.close_calls = []

    def physical(self, path, dir_fd=None, follow=False):
        if dir_fd is not None:
            self.fstat(dir_fd)
            path = self.fds[dir_fd][0].rstrip('/') + '/' + path
        if path.startswith('/tmp/'): path = '/var/volatile/tmp/' + path[5:]
        elif path.startswith('/var/tmp/'): path = '/var/volatile/tmp/' + path[9:]
        if follow and path == '/tmp': path = '/var/volatile/tmp'
        elif follow and path == '/var/tmp': path = '/var/volatile/tmp'
        return path

    def metadata(self, path):
        value = old.FakeOS.metadata(self, path)
        if stat.S_ISDIR(value.st_mode):
            prefix = path.rstrip('/') + '/'
            value.st_nlink = 2 + sum(stat.S_ISDIR(row[0]) and '/' not in name[len(prefix):]
                for name, row in self.rows.items() if name.startswith(prefix) and name != path)
        return value

    def lstat(self, path):
        if path == '/tmp/p011-mta-p2p-device.pending': return old.FakeOS.lstat(self, path)
        return old.FakeOS.lstat(self, self.physical(path))

    def stat(self, path, dir_fd=None, follow_symlinks=True):
        physical = self.physical(path, dir_fd, follow_symlinks)
        self.calls.append(('stat_at', path, dir_fd, follow_symlinks))
        if physical not in self.rows: raise OSError(errno.ENOENT, 'Fake absent')
        return self.metadata(physical)

    def readlink(self, path, dir_fd=None):
        physical = self.physical(path, dir_fd)
        self.calls.append(('readlink_at', path, dir_fd))
        if physical not in self.rows or not stat.S_ISLNK(self.rows[physical][0]):
            raise OSError(errno.EINVAL, 'Fake not link')
        return self.rows[physical][1].decode('ascii')

    def mkdir(self, path, mode, dir_fd=None):
        if dir_fd is None: raise AssertionError('staging mkdir must retain exact parent FD')
        physical = self.physical(path, dir_fd)
        self.calls.append(('mkdir_at', path, mode, dir_fd))
        if physical in self.rows: raise OSError(errno.EEXIST, 'Fake exists')
        self.rows[physical] = [stat.S_IFDIR | mode, b'', len(self.rows)+1]

    def open(self, path, flags, mode=0, dir_fd=None):
        physical = self.physical(path, dir_fd)
        self.calls.append(('open_at', path, flags, mode, dir_fd))
        if path != '/' and dir_fd is None: raise AssertionError('nonroot staging open must be relative')
        if physical in self.rows and stat.S_ISLNK(self.rows[physical][0]) and flags & self.O_NOFOLLOW:
            raise OSError(errno.ELOOP, 'Fake nofollow')
        if flags & self.O_CREAT:
            if physical in self.rows: raise OSError(errno.EEXIST, 'Fake exclusive')
            self.rows[physical] = [stat.S_IFREG | mode, b'', len(self.rows)+1]
        if physical not in self.rows: raise OSError(errno.ENOENT, 'Fake absent')
        if flags & self.O_DIRECTORY and not stat.S_ISDIR(self.rows[physical][0]):
            raise OSError(errno.ENOTDIR, 'Fake not directory')
        fd = self.next; self.next += 1; self.fds[fd] = [physical, 0]
        return fd

    def listdir(self, path):
        if type(path) is not int: raise AssertionError('listdir must use original directory FD')
        self.fstat(path)
        return old.FakeOS.listdir(self, self.fds[path][0])

    def close(self, fd):
        self.close_calls.append(fd)
        if self.close_error and self.fds[fd][0] == '/var/volatile':
            raise OSError(errno.EIO, 'Fake close unknown')
        return old.FakeOS.close(self, fd)


def run_target(pending=False, old_stage=False, broken_alias=False,
               denied_prefix=False, close_error=False, insufficient_margin=False):
    fixture = old.TargetFixture()
    fixture.actor.live = lambda: True  # Fake only, not an actual kernel fact.
    fixture.os = PathOS(pending, old_stage, broken_alias, denied_prefix, close_error)
    fixture.modules['mta_client_tmp_alias'] = alias
    executor = fixture.modules['mta_client_executor']
    executor.PHYSICAL_ROOT = '/var/volatile/tmp/p011-mta-client-rfinit'
    original_reader = executor._ReadOwner
    class ReadOwner(original_reader):
        def read_file(self, path, limit, *args, **kwargs):
            return original_reader.read_file(self, fixture.os.physical(path), limit, *args, **kwargs)
    executor._ReadOwner = ReadOwner
    if insufficient_margin:
        original = fixture.os.lstat; count = [0]
        def lstat(path):
            if path == '/tmp/p011-mta-p2p-device.pending':
                count[0] += 1
                if count[0] == 4: fixture.clock += 40.001
            return original(path)
        fixture.os.lstat = lstat
    result = target_run(fixture)
    return result, fixture


class TmpAliasV11HostTests(unittest.TestCase):
    def setUp(self):
        for name in ('subprocess.Popen', 'socket.socket', 'os.kill', 'os.fork',
                     'os.open', 'os.mkdir', 'os.unlink', 'os.rename', 'os.chmod'):
            patcher = mock.patch(name, side_effect=AssertionError('actual OS/network/staging forbidden'), create=True)
            patcher.start(); self.addCleanup(patcher.stop)

    def test_sha_protected_v10_infra_only_explicit_three_replacements_and_python35(self):
        original = (BASE / 'host/client_init_prepare_v10_p011.py').read_bytes()
        self.assertEqual(driver._INFRA_SHA, digest(original))
        reversed_code = driver._INFRA_CODE
        reversed_code = reversed_code.replace(b"'kind': 'client-init-tmp-alias-v11'", b"'kind': 'client-init-prepare-v10'", 1)
        reversed_code = reversed_code.replace(b"'MtaP011-ClientInitTmpAliasV11-'", b"'MtaP011-ClientInitPrepareV10-'", 1)
        footer = b"if __name__ == '__main__': sys.exit(main())"
        self.assertEqual(original.replace(footer, b'', 1), reversed_code)
        index = original.index(footer)
        self.assertEqual(original, reversed_code[:index] + footer + reversed_code[index:])
        for raw in (HOST.read_bytes(), Path(__file__).read_bytes()):
            ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        source, unused, values = fixture_source()
        ast.parse(source, feature_version=(3, 5))
        self.assertEqual(20, len(values['PINS']))
        self.assertLessEqual(max(len(line.encode('utf-8')) for line in source.splitlines()), 2048)
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(source))))

    def test_frozen_twenty_graph_actual_pc_loader_is_coherent_without_default_io(self):
        self.assertTrue(driver._FROZEN, 'all five owners must freeze before this one HOST batch')
        report, rows, native, manifest, unused = driver.source_check()
        self.assertTrue(report['source_check_pass']); self.assertEqual(20, report['source_count'])
        self.assertEqual(digest(HOST.read_bytes()), report['driver_sha256'])
        self.assertEqual(driver.PINS, tuple((name, pin) for name, pin, raw in rows))
        self.assertEqual(('p011_json', 'mta_ip', 'mta_client_tmp_alias'), tuple(name for name, pin in driver.PINS[:3]))
        self.assertEqual(tuple(name for name, pin in driver._V10_PINS), tuple(name for name, pin in driver.PINS if name!='mta_client_tmp_alias'))
        self.assertEqual(11, len(driver.SOURCE_LOCATIONS))
        source, unused = driver.build_source(rows, native, manifest, 'c'*32, report['driver_sha256'])
        ast.parse(source, feature_version=(3, 5))
        namespace = {'PINS': driver.PINS, 'ENCODED': tuple((name, pin, base64.b64encode(raw).decode('ascii')) for name, pin, raw in rows)}
        with mock.patch('ctypes.CDLL', side_effect=AssertionError('no actual libc construction')):
            exec(driver.LOADER, namespace)
        modules = namespace['modules']
        self.assertEqual(tuple(name for name, pin in driver.PINS), modules['mta_client_executor'].MODULES)
        phase = modules['mta_client_two_phase_lease'].TwoPhaseClientInitLease
        lease = modules['mta_client_linux_provider'].LinuxClientInitLease
        self.assertEqual((phase,), lease.__bases__); self.assertIs(phase.start, lease.start)
        self.assertEqual((60, None), lease.restore.__defaults__)
        self.assertIsNot(phase.restore, lease.restore)

    def test_default_no_execution_and_wip_missing_pin_is_unavailable(self):
        with mock.patch.object(driver, 'source_check', return_value=({'source_check_pass': True}, None, None, None, None)), \
                mock.patch.object(driver, 'execute', side_effect=AssertionError('no execute')), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, driver.main([]))
        with mock.patch.object(driver, '_FROZEN', False):
            report = driver.source_check()[0]
            self.assertFalse(report['source_check_pass']); self.assertEqual('unavailable', report['stage'])

    def test_new_target_alias_relative_publish_fullreadback_nlink_changes_close_all_originals(self):
        result, fixture = run_target()
        self.assertTrue(result['public']['pass'])  # Fake orchestration, not actual P011.
        self.assertEqual('client-init-tmp-alias-v11', fixture.values['CANDIDATE']['kind'])
        self.assertTrue(fixture.values['provider_value']['wpa_exe'].startswith('/var/volatile/tmp/p011-mta-client-rfinit/client-'))
        self.assertTrue(fixture.values['provider_value']['executor_path'].startswith('/tmp/p011-mta-client-rfinit/client-'))
        self.assertIn(('start', 20), fixture.calls); self.assertIn(('finish', 90), fixture.calls)
        self.assertEqual(295.0, fixture.values['end'])
        self.assertEqual(len(fixture.os.fds), len(fixture.os.closed))
        self.assertEqual(len(fixture.os.close_calls), len(set(fixture.os.close_calls)))
        inventory = result['private']['stage_inventory']
        self.assertEqual(32, len(inventory)); self.assertTrue(all(not r['unknown'] and r['attempted'] and r['closed'] for r in inventory))
        self.assertEqual(9, sum(r['kind']=='directory' for r in inventory))
        for path, row in fixture.os.rows.items():
            if path.startswith('/var/volatile/tmp/p011-mta-client-rfinit/') and stat.S_ISREG(row[0]):
                self.assertEqual(0o500 if path.endswith('/mta-wpa-supplicant') else 0o400, stat.S_IMODE(row[0]))
        self.assertTrue(any(r[0]=='mkdir_at' and r[3] is not None for r in fixture.os.calls))
        self.assertTrue(all(r[1]=='/' or r[4] is not None for r in fixture.os.calls if r[0]=='open_at'))
        for key in ('send_available','receive_available','phone_tested'): self.assertFalse(result['public'][key])

    def test_old_nonempty_stage_is_preserved_and_denied_before_rf_or_publish(self):
        result, fixture = run_target(old_stage=True)
        self.assertEqual('stage_exists', result['public']['reason'])
        self.assertFalse(result['public']['rf_requested']); self.assertFalse(result['public']['pass'])
        self.assertEqual(b'KEEP', fixture.os.rows['/var/volatile/tmp/p011-mta-client-rfinit/OLD'][1])
        self.assertFalse(result['private']['writes'])
        self.assertEqual(len(fixture.os.fds), len(fixture.os.closed))

    def test_wrong_fixed_alias_or_prefix_permission_denies_and_retains_partial_inventory(self):
        for keyword in ('broken_alias','denied_prefix'):
            with self.subTest(failure=keyword):
                result, fixture = run_target(**{keyword:True})
                self.assertFalse(result['public']['rf_requested']); self.assertFalse(result['public']['pass'])
                self.assertTrue(result['public']['resource_pending'])
                self.assertTrue(result['private']['stage_inventory'])
                self.assertFalse(any(row[0]=='mkdir_at' for row in fixture.os.calls))
                self.assertEqual(len(fixture.os.close_calls), len(set(fixture.os.close_calls)))

    def test_unknown_close_is_once_no_retry_no_parent_and_original_fd_is_retained(self):
        result, fixture = run_target(close_error=True)
        self.assertFalse(result['public']['rf_requested']); self.assertFalse(result['public']['staging_verified'])
        self.assertTrue(result['public']['resource_pending']); self.assertFalse(result['public']['pass'])
        inventory = result['private']['stage_inventory']
        failed = [row for row in inventory if row['name']=='volatile']
        self.assertEqual(1, len(failed)); self.assertTrue(failed[0]['attempted']); self.assertFalse(failed[0]['closed'])
        self.assertEqual(1, fixture.os.close_calls.count(failed[0]['fd']))
        self.assertNotIn(failed[0]['fd'], fixture.os.closed)
        self.assertIsNone(fixture.values['parent'])

    def test_pending_before_staging_and155_margin_keep_rf_and_parent_closed(self):
        result, fixture = run_target(pending=True)
        self.assertEqual('pending_blocked', result['public']['reason'])
        self.assertFalse(any(row[0] in ('open_at','mkdir_at') for row in fixture.os.calls))
        result, fixture = run_target(insufficient_margin=True)
        self.assertEqual('budget_before_rf', result['public']['reason'])
        self.assertTrue(result['public']['staging_verified']); self.assertFalse(result['public']['rf_requested'])
        self.assertIsNone(fixture.values['parent'])
        self.assertEqual(len(fixture.os.fds), len(fixture.os.closed))


if __name__ == '__main__': unittest.main()
