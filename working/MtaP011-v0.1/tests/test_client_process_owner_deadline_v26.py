"""One new Owner deadline method: actual bound Proc over synthetic FS/kernel.

Only Owner changes in the fixed v25 29-definition domain. Frozen fixture
definitions are reused, never their unittest methods. Actors/observations are
produced by actual Proc reads; the persist seam is NOT a durable Journal proof.
The two fake FD allocators are explicitly disjoint, not an all-namespace test.
No actual process, RF, device, complete Formal F or heap claim is made.
"""
import ast
import builtins
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import stat
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
PINS = {
    'host/client_proc_history_v24_source_manifest.json': 'dcfab972fed81b1a63bafe1a8cae6a2681d2c83d3e666bf10a827c2c7b36f70e',
    'tests/test_client_proc_absolute_deadline_v25.py': '2852349973865d3a2b09bbd4ac51862d651429a1e31bbcb363e125669b0a61b4',
    'tests/test_client_proc.py': 'fad1f4e86dd7cb6f17f8254865b75cc9389d19f89aefd8332de9ccc8d1c9c6bc',
    'tests/test_client_process_owner.py': 'dcc33004cae2a69b8bcbc3f9646fc9311c9b5dcd2da38bce045686ace14228b2',
    'candidate/client-formal-v26/runtime/mta_client_process_owner.py': '4bbf9e64f5508e6498f64d4cd8f94383612939552eb740ef46ad1354f416e27b',
}


def fixed(path, pin=None, count=None):
    raw = (BASE / path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != (pin or PINS[path]) or count is not None and len(raw) != count:
        raise ValueError('HOST fixed input changed')
    return raw


def blocked(stack):
    for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
            'ctypes.CDLL', 'os.open', 'os.read', 'os.close', 'os.fstat', 'os.lstat',
            'os.listdir', 'os.readlink', 'os.getpid', 'os.fork', 'os.execve',
            'os.kill', 'os.waitpid', 'os.system', 'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name, side_effect=AssertionError('actual OS forbidden'), create=True))


def domain():
    prior = ast.parse(fixed('tests/test_client_proc_absolute_deadline_v25.py').decode('utf-8'))
    nodes = [node.value for node in prior.body if isinstance(node, ast.Assign) and
        any(isinstance(target, ast.Name) and target.id == 'REPLACEMENTS' for target in node.targets)]
    if len(nodes) != 1: raise ValueError('HOST v25 replacement table changed')
    replacements = ast.literal_eval(nodes[0])
    if set(replacements) != {'mta_client_proc', 'mta_client_baseline',
            'mta_client_wpa_status', 'mta_client_linux_provider'}:
        raise ValueError('HOST v25 replacement shape changed')
    rows = json.loads(fixed('host/client_proc_history_v24_source_manifest.json'))['sources']
    if len(rows) != 29 or len({row['module'] for row in rows}) != 29:
        raise ValueError('HOST graph shape changed')
    modules, original = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('private definition unavailable')
            return modules[name]
        return original(name, *args, **kwargs)
    with ExitStack() as stack:
        blocked(stack)
        for row in rows:
            name = row['module']
            if name == 'mta_client_process_owner':
                path = 'candidate/client-formal-v26/runtime/' + name + '.py'
                raw = fixed(path, count=28930)
            elif name in replacements:
                path = 'candidate/client-proc-deadline-v25/runtime/' + name + '.py'
                pin, count = replacements[name]
                raw = fixed(path, pin, count)
            else:
                path = row['path']; raw = fixed(path, row['sha256'], row['bytes'])
            tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
            if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
                raise ValueError('target assertion is not an implementation gate')
            module = types.ModuleType(name); module.__file__ = str(BASE / path)
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
            modules[name] = module
            exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return modules, private_import


M, PRIVATE_IMPORT = domain()


def fixture(path):
    tree = ast.parse(fixed(path).decode('utf-8'))
    # Reuse the frozen concrete FS/kernel definitions, excluding ALL old methods.
    tree.body = [node for node in tree.body if not isinstance(node, ast.If) and not (
        isinstance(node, ast.ClassDef) and any(isinstance(base, ast.Attribute) and
            base.attr == 'TestCase' for base in node.bases))]
    module = types.ModuleType('HOST_v26_' + Path(path).stem)
    module.__file__ = str(BASE / path)
    module.__dict__['__builtins__'] = dict(vars(builtins), __import__=PRIVATE_IMPORT)
    with ExitStack() as stack:
        blocked(stack)
        exec(compile(tree, module.__file__, 'exec'), module.__dict__)
    return module


FS, K = fixture('tests/test_client_proc.py'), fixture('tests/test_client_process_owner.py')
p, o, s, core, b = (M[name] for name in ('mta_client_proc', 'mta_client_process_owner',
    'mta_client_store', 'mta_p2p_client_init', 'mta_client_resource_budget'))


class ProcessOwnerDeadlineV26Tests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack(); self.addCleanup(stack.close); blocked(stack)

    def make(self):
        clock, fs = K.FakeClock(), FS.FakeFs()
        clock.value = 1.0
        fs.fd = 1000  # Synthetic disjoint namespaces, not a physical FD-domain claim.
        store = s.DurableClientInitStore('a' * 32, core.Identity('a' * 64), _clock=clock)
        reader = p.ProcReader(_clock=clock, _fs=fs)
        store._resource_budget_v23.bind_reader(reader)
        def install_child(pid):
            root = '/proc/' + str(pid)
            fs.dirs.update((root, root + '/task', root + '/task/' + str(pid)))
            fs.files[root + '/stat'] = FS.stat_data(pid, start=200)
            fs.files[root + '/task/' + str(pid) + '/stat'] = FS.stat_data(pid, start=200)
            fs.files[root + '/cmdline'] = fs.files['/proc/42/cmdline']
            fs.links[root + '/exe'] = fs.links['/proc/42/exe']
        def remove_child(pid):
            root = '/proc/' + str(pid)
            for mapping in (fs.files, fs.links):
                for path in list(mapping):
                    if path == root or path.startswith(root + '/'): del mapping[path]
            fs.dirs = {path for path in fs.dirs if path != root and not path.startswith(root + '/')}
        class Kernel(K.FakeKernel):
            def getpid(self): return 42
            def fork(self):
                pid = super(Kernel, self).fork()
                if type(pid) is int and pid > 0: install_child(pid)
                return pid
            def waitpid(self, pid, flags):
                result = super(Kernel, self).waitpid(pid, flags)
                if type(result) is tuple and result[0] == pid: remove_child(pid)
                return result
        kernel = Kernel(clock)
        owner = o.DirectChildOwner(_os=kernel, _reader=reader, _clock=clock,
            _threads=lambda: 1, _flags=kernel.flags)
        spec = o.LaunchSpec('controller', '/private/controller',
            ('/private/controller', '--private'), (('LANG', 'C'),), K.SHA)
        ticket = owner.register(spec, 3, 21.0)
        return clock, fs, store, reader, kernel, owner, ticket

    def test_actual_bound_owner_active_and_cleanup_caps_never_renew_observation_scope(self):
        clock, fs, store, reader, kernel, owner, ticket = self.make()
        self.assertIs(ticket, owner.launch(ticket, _absolute_deadline=1.8))
        self.assertTrue(owner.release(ticket, lambda t, a: o.PersistReceipt(t, a), _absolute_deadline=2.0))
        self.assertIs(type(ticket.parent), core.Actor)
        self.assertIs(type(ticket.preexec), core.Actor)
        self.assertEqual([1.8] * 3 + [2.0] * 3,
            [generation.absolute_deadline for generation in reader.operation_history])
        self.assertTrue(reader.history_closed()); self.assertFalse(fs.live)
        self.assertFalse(store._attempted); self.assertFalse(owner.status()['provider_ready'])
        clock.value = 22.0  # Original active deadline has expired; no new active grant.
        before = tuple(fs.operations)
        with self.assertRaisesRegex(o.ProcessOwnerError, '^deadline$'): owner.resolve(ticket)
        self.assertEqual(before, tuple(fs.operations)); self.assertIsNone(ticket.postexec)
        with store._mutex:
            store._resource_lane_v23 = b.CLEANUP
            store._resource_budget_v23.cancel()
        self.assertTrue(owner.wait_reap(ticket, timeout=20, _absolute_deadline=25.0))
        self.assertTrue(owner.fresh_exit(ticket, _absolute_deadline=25.0))
        self.assertTrue(owner.close_inventory(ticket, _absolute_deadline=25.0))
        self.assertTrue(ticket.waited); self.assertTrue(ticket.exit_verified)
        self.assertEqual([25.0] * 4,
            [generation.absolute_deadline for generation in reader.operation_history[-4:]])
        self.assertTrue(all(generation.credit.lane == b.CLEANUP for generation in reader.operation_history[-4:]))
        self.assertTrue(reader.history_closed()); self.assertFalse(fs.live)
        self.assertTrue(all(ticket.reader.closed_open_ticket(ticket) for generation in reader.operation_history
            for ticket in generation.tickets))
        self.assertEqual({3}, set(kernel.live)); self.assertFalse(owner.status()['complete'])

        # In-flight actual Proc read crosses the shorter active cap. Its close
        # finally remains allowed, but neither fork nor a later observation IO.
        clock, fs, store, reader, kernel, owner, ticket = self.make()
        events, crossed = [], []
        def late_read(unused, operation, path, count):
            events.append((operation, clock(), path))
            if operation == 'read' and not crossed:
                crossed.append(True); clock.value = 1.201
        fs.hook = late_read
        with self.assertRaisesRegex(o.ProcessOwnerError, '^deadline$'):
            owner.launch(ticket, _absolute_deadline=1.2)
        self.assertTrue(crossed)
        self.assertFalse([(op, when) for op, when, path in events if when >= 1.2])
        self.assertFalse(any(row[0] == 'fork' for row in kernel.calls))
        self.assertFalse(fs.live); self.assertEqual(len(fs.opens), len(fs.closed))
        self.assertTrue(reader.history_closed()); self.assertFalse(owner._active)
        self.assertEqual(1.2, reader.operation_history[-1].absolute_deadline)

        # A real synthetic wait return is retained before its late postcheck.
        # The same expired total cap cannot be renewed by fresh_exit's now+3.
        clock, fs, store, reader, kernel, owner, ticket = self.make()
        owner.launch(ticket); owner.release(ticket, lambda t, a: o.PersistReceipt(t, a))
        clock.value = 22.0
        with store._mutex:
            store._resource_lane_v23 = b.CLEANUP
            store._resource_budget_v23.cancel()
        def late_wait(operation, args):
            if operation == 'waitpid': clock.value = 25.001
        kernel.hook = late_wait
        with self.assertRaisesRegex(o.ProcessOwnerError, '^deadline$'):
            owner.wait_reap(ticket, timeout=20, _absolute_deadline=25.0)
        self.assertTrue(ticket.waited); self.assertEqual('direct_child_reaped', ticket.stage)
        self.assertEqual(0, ticket.exit_code); self.assertFalse(ticket.exit_verified)
        before = tuple(fs.operations)
        with self.assertRaisesRegex(o.ProcessOwnerError, '^deadline$'):
            owner.fresh_exit(ticket, _absolute_deadline=25.0)
        self.assertEqual(before, tuple(fs.operations)); self.assertFalse(ticket.exit_verified)
        self.assertEqual(25.0, reader.operation_history[-1].absolute_deadline)
        self.assertEqual(0, store._resource_budget_v23.status()['active_producers'])
        self.assertFalse(owner.status()['complete']); self.assertFalse(owner.status()['provider_ready'])
        print('HOST_V26_OWNER_CAPS active_short_cap_cleanup_independent_late_read_closed_late_reap_retained')


if __name__ == '__main__': unittest.main()
