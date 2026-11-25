"""New actual v24 graph hooks over FakeFs; no init/network/device acceptance.

Only fixture definitions are reused. No earlier unittest method is executed.
Four isolated replacements are parsed as Python 3.5 in the frozen v23 graph.
Formal F remains the old 24-source graph and is not called or rewired here.
"""
import ast
import builtins
from contextlib import ExitStack
import hashlib
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
NEW = BASE / 'candidate/client-proc-history-v24/runtime'
sys.path.insert(0, str(BASE / 'tests'))


def blocked(stack):
    for name in ('socket.socket', 'subprocess.Popen', 'ctypes.CDLL', 'os.open',
            'os.kill', 'os.waitpid', 'os.system', 'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name, side_effect=AssertionError('actual OS forbidden'), create=True))


def domain():
    path = BASE / 'host/client_resource_v23_source_check.py'
    if hashlib.sha256(path.read_bytes()).hexdigest() != '97e746b9df86774163f2957b6df41ddd28f4918d5ae0b94d2b9d7798de35e23d':
        raise ValueError('previous checker drift')
    spec = importlib.util.spec_from_file_location('HOST_v24_previous_source_checker', str(path))
    check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)
    rows = check.verify()
    budget_row = next(r for r in rows if r['module'] == 'mta_client_resource_budget')
    rows = [r for r in rows if r is not budget_row]
    rows.insert(next(i for i, r in enumerate(rows) if r['module'] == 'mta_client_proc'), budget_row)
    changed = {'mta_client_proc', 'mta_client_resource_budget', 'mta_client_store', 'mta_client_linux_provider'}
    modules, pins, imported = {}, {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('private graph dependency unavailable')
            return modules[name]
        return imported(name, *args, **kwargs)
    with ExitStack() as stack:
        blocked(stack)
        for row in rows:
            path = NEW / (row['module'] + '.py') if row['module'] in changed else BASE / row['path']
            raw = path.read_bytes(); digest = hashlib.sha256(raw).hexdigest()
            if row['module'] not in changed and (digest != row['sha256'] or len(raw) != row['bytes']):
                raise ValueError('unchanged source drift')
            ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
            module = types.ModuleType(row['module']); module.__file__ = str(path)
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
            modules[row['module']] = module
            exec(compile(raw, str(path), 'exec'), module.__dict__)
            pins[row['module']] = digest
    return modules, pins


M, SOURCE_PINS = domain()
raw = (BASE / 'tests/test_client_durable_connect_v19.py').read_bytes()
if hashlib.sha256(raw).hexdigest() != 'f92ab1be262d6da641e4cc3306f218f44d1c500f70c35d0352017cbae396bab1':
    raise ValueError('fixture definition drift')
text = raw.decode('utf-8')
if text.count('M = graph()') != 1: raise ValueError('fixture graph scope changed')
fixture = types.ModuleType('HOST_v24_fixture_definitions')
fixture.__file__ = str(BASE / 'tests/test_client_durable_connect_v19.py')
fixture.HOST_GRAPH = M
with ExitStack() as stack:
    blocked(stack)
    exec(compile(text.replace('M = graph()', 'M = HOST_GRAPH'), fixture.__file__, 'exec'), fixture.__dict__)

import test_client_proc as fs_fixture
proc, stores, provider_source = (M[n] for n in
    ('mta_client_proc', 'mta_client_store', 'mta_client_linux_provider'))


class ProcHistoryIntegrationV24Tests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack(); self.addCleanup(stack.close); blocked(stack)

    def make(self, _owner_reader=None, _capture=None):
        marker_fs, owner_fs = fs_fixture.FakeFs(), fs_fixture.FakeFs()
        marker = proc.ProcReader(_fs=marker_fs, _clock=lambda: 1.0)
        store = stores.DurableClientInitStore(fixture.old.TOKEN, fixture.IDENTITY,
            _proc_reader=marker, _clock=lambda: 1.0)
        store._begin_io()  # Start an actual scoped Store deadline; no ready-stage injection.
        provider = provider_source.LinuxClientInitProvider(fixture.manifest(), _clock=lambda: 1.0,
            _proc_factory=lambda **kw: proc.ProcReader(_fs=fs_fixture.FakeFs(), **kw))
        owner = M['mta_client_process_owner'].DirectChildOwner(
            _reader=_owner_reader if _owner_reader is not None else
                proc.ProcReader(_fs=owner_fs, _clock=lambda: 1.0), _clock=lambda: 1.0)
        bridge = provider_source.LinuxDirectChildLaunchBridge(store, owner, provider.specs(), provider)
        lease = provider_source.LinuxClientInitLease(provider, store, fixture.IDENTITY, lambda: 1.0, bridge)
        if _capture is not None: _capture.update(store=store, provider=provider, owner=owner)
        provider.attach(store, owner, bridge, lease)
        return store, provider, owner, marker_fs

    def test_actual_store_marker_and_provider_owner_hooks_consume_all_original_generations(self):
        store, provider, owner, fs = self.make()
        self.assertEqual([], fs.operations)
        self.assertIs(store._proc_reader._resource_budget_v24, store._resource_budget_v23)
        self.assertIs(owner._reader._resource_budget_v24, store._resource_budget_v23)
        first = store._proc_reader.read_self(); second = store._proc_reader.read_self()
        owner._reader.read_self()
        generations = store._proc_reader.operation_history
        self.assertEqual(2, len(generations))
        self.assertIs(generations[0].observation, first); self.assertIs(generations[1].observation, second)
        self.assertTrue(store._inventory_closed())
        self.assertTrue(provider._remember_proc_history_v24(store._proc_reader))
        self.assertTrue(provider._remember_proc_history_v24(owner._reader))
        self.assertTrue(provider._proof().complete())
        self.assertEqual([], provider._fd_receipts)  # Exact PROC_OPEN originals are not late duplicate receipts.
        original = generations[0].tickets[0]
        original.ebadf_observed = False
        try:
            self.assertFalse(store._inventory_closed())
            self.assertFalse(provider._proof().complete())
        finally: original.ebadf_observed = True
        self.assertEqual(24, len(M['mta_client_executor'].MODULES)); self.assertEqual(29, len(M))
        self.assertFalse(provider.status()['send_available'])

    def test_provider_new_factory_retains_malformed_or_borrowed_reader_before_refusal(self):
        store, provider, owner, fs = self.make()
        reader = provider._new_proc_v24(timeout=3, _clock=lambda: 1.0)
        self.assertIs(type(reader), proc.ProcReader)
        self.assertIs(reader._resource_budget_v24, store._resource_budget_v23)
        with mock.patch.object(provider, '_proc_factory', return_value=reader):
            with self.assertRaisesRegex(provider_source.LinuxProviderError, 'actor_unknown'):
                provider._new_proc_v24(timeout=3, _clock=lambda: 1.0)
        row = provider._proc_readers_v24[-1]
        self.assertIs(row['reader'], reader); self.assertTrue(row['returned']); self.assertTrue(row['unknown'])
        self.assertEqual((), reader.operation_history)
        self.assertTrue(provider.status()['resource_pending'])
        self.assertFalse(provider._proof().complete())
        self.assertTrue(row['unknown'])  # Closure checks do not wash an unknown factory root.
        for mode in ('no_return', 'malformed'):
            with self.subTest(mode=mode):
                store, provider, owner, fs = self.make()
                bad = object()
                kwargs = {'side_effect': RuntimeError('injected factory failure')} if mode == 'no_return' else {'return_value': bad}
                error = RuntimeError if mode == 'no_return' else provider_source.LinuxProviderError
                with mock.patch.object(provider, '_proc_factory', **kwargs):
                    with self.assertRaises(error): provider._new_proc_v24(timeout=3, _clock=lambda: 1.0)
                row = provider._proc_readers_v24[-1]
                self.assertEqual(mode != 'no_return', row['returned'])
                self.assertIs(row['reader'], None if mode == 'no_return' else bad)
                self.assertTrue(row['unknown'])
                self.assertTrue(provider.status()['resource_pending'])
                self.assertFalse(provider._proof().complete())
                self.assertEqual([], fs.operations)

    def test_current_numeric_reuse_still_requires_one_actual_registered_live_owner(self):
        store, provider, owner, fs = self.make()
        store._proc_reader.read_self()
        ticket = store._proc_reader.operation_history[0].tickets[0]
        self.assertTrue(provider._closed_fd(ticket.fs, ticket.descriptor, ticket))
        # Unknown live FakeFs reuse is not authenticated by matching a number.
        fs.live[ticket.descriptor] = [ticket.path, fs.files[ticket.path], 0]
        self.assertFalse(provider._closed_fd(ticket.fs, ticket.descriptor, ticket))
        self.assertEqual(ticket.descriptor, ticket.fd)
        self.assertTrue(ticket.reader.closed_open_ticket(ticket))  # Historical close stays distinct.
        self.assertFalse(provider._proof().complete())

    def test_changed_namespace_or_failed_owner_binding_cannot_sign_complete(self):
        for root in ('owner', 'store'):
            with self.subTest(root=root):
                store, provider, owner, fs = self.make()
                borrowed = provider._new_proc_v24(timeout=3, _clock=lambda: 1.0)
                if root == 'owner': owner._reader = borrowed
                else: store._proc_reader = borrowed
                self.assertTrue(provider.status()['resource_pending'])
                self.assertFalse(provider._proof().complete())
                if root == 'store': self.assertFalse(store._inventory_closed())
        foreign_store, foreign_provider, foreign_owner, foreign_fs = self.make()
        captured = {}
        with self.assertRaises(M['mta_client_resource_budget'].ResourceBudgetError):
            self.make(_owner_reader=foreign_store._proc_reader, _capture=captured)
        provider = captured['provider']
        self.assertIs(provider._owner_proc_reader_v24, foreign_store._proc_reader)
        self.assertTrue(provider.status()['resource_pending'])
        self.assertFalse(provider._proof().complete())

    def test_passive_status_reports_actual_marker_owner_active_and_unknown_history_without_io(self):
        for root in ('marker', 'owner'):
            with self.subTest(root=root):
                store, provider, owner, fs = self.make()
                reader = store._proc_reader if root == 'marker' else owner._reader
                fs, observed = reader._fs, []
                def reenter(unused, operation, path, count):
                    if operation != 'read': return
                    before = tuple(fs.operations)
                    pending = provider.status()['resource_pending']
                    marker_pending = store.status()['resource_pending']
                    observed.append((pending, marker_pending))
                    self.assertEqual(before, tuple(fs.operations))  # status is strictly passive.
                fs.hook = reenter
                self.assertEqual('live_actor', reader.read_self().kind)
                self.assertTrue(observed)
                self.assertTrue(all(pending for pending, marker_pending in observed))
                if root == 'marker': self.assertTrue(all(marker_pending for pending, marker_pending in observed))
                self.assertFalse(provider.status()['resource_pending'])
                self.assertFalse(store.status()['resource_pending'])
                fs.hook = None
                fs.read_result = {'HOST retained invalid original': b'bad'}
                self.assertTrue(reader.read_self().resource_pending)
                self.assertTrue(provider.status()['resource_pending'])
                if root == 'marker': self.assertTrue(store.status()['resource_pending'])


if __name__ == '__main__': unittest.main()
