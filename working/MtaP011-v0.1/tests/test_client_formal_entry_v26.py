"""New v26 entry methods only; actual Loader/Store/Proc over synthetic IO.

This stage replaces only Executor in the frozen v25 29-definition graph.
Provider/DORA/Owner v26 integration is a separate affected stage. No old test
method runs. No process execution, RF, device, phone or recovery is claimed.
"""
import ast
import errno
import hashlib
import importlib
import json
from pathlib import Path
import stat
import sys
import types
import unittest
from contextlib import ExitStack
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))
PINS = {
    'tests/test_client_proc_absolute_deadline_v25.py': '2852349973865d3a2b09bbd4ac51862d651429a1e31bbcb363e125669b0a61b4',
    'tests/test_client_executor.py': '85caf5c2aba6d93a1d6fcaf14d4cf387c1a42435b85071a05c505192b13c19ce',
    'host/client_proc_history_v24_source_manifest.json': 'dcfab972fed81b1a63bafe1a8cae6a2681d2c83d3e666bf10a827c2c7b36f70e',
    'candidate/client-formal-v26/runtime/mta_client_executor.py': '81aa0ba096325b4f6928d1968fa9f24395951b1af4ce37c6d8ba6948f70b574e',
    'native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant': 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301',
}


def fixed(path, digest=None):
    raw = (BASE / path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != (digest or PINS[path]):
        raise ValueError('HOST input changed')
    return raw


fixed('tests/test_client_proc_absolute_deadline_v25.py')
fixed('tests/test_client_executor.py')
v25 = importlib.import_module('test_client_proc_absolute_deadline_v25')
ff = importlib.import_module('test_client_executor')
fs_helpers = v25.definitions.fs_fixture
f = types.ModuleType('HOST_formal_entry_v26')
f.__file__ = str(BASE / 'candidate/client-formal-v26/runtime/mta_client_executor.py')
raw = fixed('candidate/client-formal-v26/runtime/mta_client_executor.py')
ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
exec(compile(raw, f.__file__, 'exec'), f.__dict__)


def sources():
    rows = json.loads(fixed('host/client_proc_history_v24_source_manifest.json'))['sources']
    result = {}
    for row in rows:
        name = row['module']
        if name == 'mta_client_executor':
            raw = fixed('candidate/client-formal-v26/runtime/mta_client_executor.py')
        elif name in v25.REPLACEMENTS:
            pin, count = v25.REPLACEMENTS[name]
            raw = fixed('candidate/client-proc-deadline-v25/runtime/' + name + '.py', pin)
            if len(raw) != count: raise ValueError('HOST source length changed')
        else:
            raw = fixed(row['path'], row['sha256'])
            if len(raw) != row['bytes']: raise ValueError('HOST source length changed')
        ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        result[name] = raw
    if tuple(result) != f.MODULES: raise ValueError('HOST module order changed')
    return result


def deployment(clock):
    io = ff.FakeIo(clock)
    token, candidate = 'a' * 32, 'a' * 64
    run = f.ROOT + '/client-' + token
    inputs = sources()
    python = b'\x7fELFHOST-v26-synthetic-python-not-a-device-image'
    native = fixed('native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant')
    io.add('/usr/bin/python3.5', python, 0o755)
    pm = {'version': 1, 'run_token': token, 'candidate_sha': candidate,
        'ifname': 'mta00000000', 'baseline_manifest': list(v25.M['mta_p2p_client_init'].STOCK_PINS) +
            [(v25.M['mta_client_baseline'].CLI, 'b' * 64)],
        'status_manifest': {'daemon_exe': '/usr/sbin/wpa_supplicant', 'daemon_sha256': 'c' * 64,
            'endpoint': '/var/run/wpa_supplicant/wlan0', 'real_uid': 0, 'real_gid': 0,
            'namespace_kind': 'namespaces_disabled_cgroup_mnt', 'config_sha256': 'd' * 64},
        'wpa_exe': f.PHYSICAL_ROOT + '/client-' + token + '/native/mta-wpa-supplicant',
        'wpa_sha': hashlib.sha256(native).hexdigest(), 'python_exe': '/usr/bin/python3.5',
        'python_sha': hashlib.sha256(python).hexdigest(),
        'executor_path': run + '/runtime/mta_client_executor.py',
        'executor_sha': hashlib.sha256(inputs['mta_client_executor']).hexdigest()}
    binding = {'version': 1, 'run_token': token, 'candidate_sha': candidate,
        'operation_id': 'HOST-v26-operation', 'native_epoch': 8, 'operation_epoch': 8,
        'gatt_session': 12, 'nonce': 'd' * 32, 'receive_consent': True}
    tree = {'version': 2, 'provider': pm, 'connect_binding': binding,
        'sources': [[name, hashlib.sha256(inputs[name]).hexdigest()] for name in f.MODULES]}
    for name, data in inputs.items(): io.add(run + '/runtime/' + name + '.py', data)
    io.add(pm['wpa_exe'], native, 0o500)
    original_stat = io.stat
    links = {'/tmp': '/var/tmp', '/var/tmp': '/var/volatile/tmp'}
    def stat_at(path):
        if path.startswith(f.ROOT + '/'):
            physical = f.PHYSICAL_ROOT + path[len(f.ROOT):]
            if physical in io.files: return io.files[physical][1]
        if path in links:
            row = ff.metadata(stat.S_IFLNK | 0o777, len(links[path]), ino=hash(path) & 0xffff)
            row.st_mtime_ns = row.st_ctime_ns = 100
            return row
        if path in ('/var/volatile', '/var/volatile/tmp'):
            return ff.metadata(stat.S_IFDIR | 0o1777, ino=hash(path) & 0xffff)
        if path == f.PHYSICAL_ROOT or path.startswith(f.PHYSICAL_ROOT + '/'):
            if path in io.files: return io.files[path][1]
            return original_stat(f.ROOT + path[len(f.PHYSICAL_ROOT):])
        return original_stat(path)
    io.stat, io.readlink = stat_at, lambda path: links[path]
    wire = json.dumps(tree, sort_keys=True).encode('ascii')
    io.add(run + '/deployment.json', wire)
    loader = f.DeploymentLoader(token, hashlib.sha256(wire).hexdigest(), io, clock)
    return loader.load(), io


def install(fs, pid, exe, argv, start=100):
    root = '/proc/' + str(pid)
    fs.dirs.update((root, root + '/task', root + '/task/' + str(pid)))
    fs.files[root + '/stat'] = fs_helpers.stat_data(pid, start=start)
    fs.files[root + '/task/' + str(pid) + '/stat'] = fs_helpers.stat_data(pid, start=start)
    fs.files[root + '/cmdline'] = b'\0'.join(x.encode('ascii') for x in argv) + b'\0'
    fs.links[root + '/exe'] = exe


class FormalEntryV26Tests(unittest.TestCase):
    def setUp(self):
        self.clock = ff.Clock()
        stack = ExitStack(); self.addCleanup(stack.close)
        for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
                'ctypes.CDLL', 'os.open', 'os.read', 'os.close', 'os.fstat',
                'os.lstat', 'os.listdir', 'os.readlink', 'os.getpid', 'os.fork',
                'os.execve', 'os.kill', 'os.waitpid', 'os.system',
                'threading.Thread.start', 'time.sleep'):
            stack.enter_context(mock.patch(name, side_effect=AssertionError('actual OS forbidden'), create=True))

    def test_actual_loader_29_fixed_sources_33_reads_and_no_recursive_executor(self):
        dep, io = deployment(self.clock)
        self.assertEqual(29, len(f.MODULES))
        self.assertEqual(33, len(dep.loader.owner.rows))
        self.assertEqual(set(f.MODULES) - {'mta_client_executor'}, set(dep.modules))
        self.assertIn('mta_client_dora', dep.modules)
        self.assertIn('mta_client_resource_budget', dep.modules)
        self.assertIsNone(dep.loader.authenticate(dep))
        self.assertTrue(all(row['closed'] and not row['unknown'] for row in dep.loader.owner.rows))
        self.assertEqual(0, io.created_count)

    def test_exact_process_local_budget_and_original_history_ignore_numeric_reuse(self):
        dep, io = deployment(self.clock)
        fs = fs_helpers.FakeFs()
        entry = f._ProcEntry(dep, self.clock, self.clock() + 10, fs)
        f._pure_proc_store(entry)
        result = f._observe(entry, dep.modules['mta_client_proc'], 'read_self')
        self.assertEqual('live_actor', result.kind)
        self.assertFalse(entry.proc_store._attempted)
        self.assertIs(entry.reader._bound_budget_v24, entry.proc_budget)
        generation = entry.reader.operation_history[0]
        self.assertEqual(110.0, generation.absolute_deadline)
        self.assertIs(generation.credit._store, entry.proc_store)
        self.assertTrue(f._reader_closed(entry.reader, dep.modules['mta_client_proc']))
        fd = generation.tickets[0].descriptor
        fs.live[fd] = ['/proc/42/stat', fs.files['/proc/42/stat'], 0]
        before = list(fs.operations)
        self.assertTrue(f._reader_closed(entry.reader, dep.modules['mta_client_proc']))
        self.assertEqual(before, fs.operations)
        self.assertIn(fd, fs.live)  # caller-owned reused FD is not closed/probed

    def test_known_pure_assembly_bad_entry_never_starts_or_restores_or_acquires(self):
        dep, io = deployment(self.clock)
        modules = dep.modules
        with mock.patch.object(modules['mta_client_linux_provider'].LinuxClientInitLease,
                'start', side_effect=AssertionError('entry cannot start')), \
                mock.patch.object(modules['mta_client_linux_provider'].LinuxClientInitLease,
                'restore', side_effect=AssertionError('entry cannot recover')), \
                mock.patch.object(modules['mta_client_store'].DurableClientInitStore,
                'acquire', side_effect=AssertionError('entry cannot acquire')):
            child = f.ClientExecutor(dep, io, self.clock, _proc_fs=fs_helpers.FakeFs(),
                _environ={'P011_CLIENT_EXECUTABLE_FD': '60'})
            result = child.run()
        self.assertIsNotNone(child.assembly)
        self.assertFalse(child.assembly_ticket['unknown'])
        self.assertFalse(child.start_call_started)
        self.assertFalse(child.proc_store._attempted)
        self.assertFalse(result['done'])
        self.assertEqual('actor_unknown', result['reason'])
        self.assertIsNone(child.finish)
        self.assertIsNone(child.recovery_until)
        self.assertTrue(all(f._reader_closed(row['reader'], modules['mta_client_proc']) for row in child.reader_rows))

    def test_parent_real_proc_setup_and_absence_share_scopes_not_success_frames(self):
        dep, io = deployment(self.clock)
        fs = fs_helpers.FakeFs()
        class Process(ff.FakeProcess):
            def wait(self, timeout):
                code = super(Process, self).wait(timeout)
                root = '/proc/' + str(self.pid)
                for mapping in (fs.files, fs.links):
                    for path in list(mapping):
                        if path == root or path.startswith(root + '/'): del mapping[path]
                fs.dirs = {path for path in fs.dirs if path != root and not path.startswith(root + '/')}
                return code
        def popen(argv, executable_fd):
            io.created_count += 1; io.argv = argv
            value = Process(io); io.created = value
            install(fs, value.pid, dep.manifest.python_exe, argv)
            return value
        io.process_type, io.popen = Process, popen
        parent = f.ParentExecutor(dep, io, self.clock, _proc_fs=fs)
        result = parent.start()
        self.assertEqual(1, io.created_count)
        self.assertEqual('not_started', result['reason'])
        self.assertEqual([110.0, 110.0], [row['deadline'] for row in parent.reader_rows])
        self.assertEqual(110.0, parent.file_owner.deadline)
        self.assertFalse(parent.proc_store._attempted)
        result = parent.finish(timeout=5)
        self.assertTrue(result['parent_waited'])
        self.assertTrue(result['parent_absence_verified'])
        self.assertTrue(result['parent_resources_closed'])
        self.assertFalse(result['done'])  # no real F FinishReceipt, no success frame
        self.assertEqual('child_pending', result['reason'])
        self.assertEqual(105.0, parent.reader_rows[-1]['deadline'])
        self.assertEqual('CLEANUP', parent.reader_rows[-1]['reader'].operation_history[0].credit.lane)

    def test_watchdog_budget_bound_before_proc_and_original_ttl_not_renewed(self):
        dep, io = deployment(self.clock)
        fs = fs_helpers.FakeFs()
        install(fs, 42, dep.manifest.python_exe, f._argv(dep, '--watchdog', '20.0'))
        io.fds[60] = {'meta': ff.metadata(stat.S_IFREG | 0o600), 'data': b'', 'position': 0}
        io.fds[61] = {'meta': ff.metadata(stat.S_IFIFO | 0o600), 'data': b'', 'position': 0}
        advanced = []
        def hook(used, operation, path, count):
            if operation == 'read' and not advanced:
                self.clock.value += 2; advanced.append(True)
        fs.hook = hook
        before = len(f._ENTRY_OWNERS)
        result = f.watchdog(dep, 20, io, self.clock,
            {'P011_CLIENT_DEVICE_FD': '60', 'P011_CLIENT_NOTIFY_FD': '61'}, '20.0', fs)
        entry = f._ENTRY_OWNERS[before]
        self.assertEqual(0, result)
        self.assertEqual(120.0, entry.reader_rows[0]['deadline'])
        self.assertIs(entry.reader._bound_budget_v24, entry.proc_budget)
        self.assertFalse(entry.proc_store._attempted)
        self.assertAlmostEqual(120.0, self.clock.value, places=5)
        self.assertEqual((61, b'R'), io.writes[-1])
        self.assertIn(60, io.fds); self.assertIn(61, io.fds)  # borrowed, not closed by watchdog


if __name__ == '__main__': unittest.main()
