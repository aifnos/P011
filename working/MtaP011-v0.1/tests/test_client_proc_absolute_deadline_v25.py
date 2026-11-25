"""New scoped HOST deadline regression; no collector/network/device claim.

Isolated v25 Proc/Baseline/Status/Provider and frozen v24 Store/budget
run over explicit FakeFs. One completed read precedes the affected reused
reader call. An in-flight read advances a synthetic clock across the original
outer deadline; close/readback remain allowed, new observation IO must stop.
No ready Journal, Handle, ProcObservation or platform permission is injected.
"""
from contextlib import ExitStack
import ast
import builtins
import hashlib
import importlib
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))
PRIOR_TEST_SHA = '53401eece502dec95d6fa46f254075cd0b10d34e2e2aa718a3f3565f73b25369'
prior = BASE / 'tests/test_client_proc_history_integration_v24.py'
if hashlib.sha256(prior.read_bytes()).hexdigest() != PRIOR_TEST_SHA:
    raise ValueError('frozen fixture definitions changed')
definitions = importlib.import_module('test_client_proc_history_integration_v24')
MANIFEST_SHA = 'dcfab972fed81b1a63bafe1a8cae6a2681d2c83d3e666bf10a827c2c7b36f70e'
NEW = BASE / 'candidate/client-proc-deadline-v25/runtime'
REPLACEMENTS = {
    'mta_client_proc': ('ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6', 39384),
    'mta_client_baseline': ('b74696eb4fa0586b254633f667eb588634700234cc30d8b49d5453e4592782bf', 29510),
    'mta_client_wpa_status': ('47074a5af8d9f75746fa7cd72e1e42b50c8402fcbb612963f6523c875fe1c269', 39133),
    'mta_client_linux_provider': ('ca8b7055aaa8eb4d54496286c6394bc58cf195569f9acc81fe4d4c7b6a139e5e', 131611),
}


def domain():
    raw = (BASE / 'host/client_proc_history_v24_source_manifest.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA:
        raise ValueError('frozen graph manifest changed')
    rows = json.loads(raw.decode('utf-8'))['sources']
    if len(rows) != 29 or len({row['module'] for row in rows}) != 29:
        raise ValueError('graph shape changed')
    modules, imported = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('private dependency unavailable')
            return modules[name]
        return imported(name, *args, **kwargs)
    with ExitStack() as stack:
        definitions.blocked(stack)
        for row in rows:
            path = NEW / (row['module'] + '.py') if row['module'] in REPLACEMENTS else BASE / row['path']
            digest, count = REPLACEMENTS.get(row['module'], (row['sha256'], row['bytes']))
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != digest or len(raw) != count:
                raise ValueError('fixed source changed')
            tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
            if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
                raise ValueError('target contains assertion')
            module = types.ModuleType(row['module']); module.__file__ = str(path)
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
            modules[row['module']] = module
            exec(compile(raw, str(path), 'exec'), module.__dict__)
    return modules


M = domain()  # Definitions only, no earlier test method runs.
p, b, s, baseline, status = (M[name] for name in ('mta_client_proc',
    'mta_client_resource_budget', 'mta_client_store', 'mta_client_baseline', 'mta_client_wpa_status'))


class Clock(object):
    def __init__(self): self.value = 1.0
    def __call__(self): return self.value


class ProcAbsoluteDeadlineV25Tests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack(); self.addCleanup(stack.close)
        for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
                'ctypes.CDLL', 'os.open', 'os.read', 'os.close', 'os.fstat',
                'os.lstat', 'os.listdir', 'os.readlink', 'os.getpid', 'os.fork',
                'os.execve', 'os.kill', 'os.waitpid', 'os.system',
                'threading.Thread.start', 'time.sleep'):
            stack.enter_context(mock.patch(name, side_effect=AssertionError('actual OS forbidden'), create=True))

    def make_reader(self, timeout=3.0):
        clock, fs = Clock(), definitions.fs_fixture.FakeFs()
        store = s.DurableClientInitStore(definitions.fixture.old.TOKEN,
            M['mta_p2p_client_init'].Identity(definitions.fixture.IDENTITY.candidate_sha), _clock=clock)
        reader = p.ProcReader(_fs=fs, _clock=clock, timeout=timeout)
        store._resource_budget_v23.bind_reader(reader)
        return clock, fs, store, reader

    def test_original_deadline_owner_links_and_established_cap_before_proc_enumeration(self):
        provider_source = M['mta_client_linux_provider']
        def make_provider():
            _, fs, store, unused = self.make_reader()
            io = types.SimpleNamespace(listdir=mock.Mock(return_value=['42']))
            old_manifest = definitions.fixture.manifest()
            values = {key: getattr(old_manifest, key) for key in provider_source._KEYS}
            values['status_manifest'] = dict(values['status_manifest'])
            manifest = provider_source.ProviderManifest(values, _manifest_sha256=old_manifest.manifest_sha256)
            provider = provider_source.LinuxClientInitProvider(manifest, _io=io, _clock=lambda: 1.0,
                _proc_factory=lambda **kw: p.ProcReader(_fs=fs, **kw))
            provider._store = store  # Pure component attachment only; no ready or network stage.
            store._resource_budget_v23.bind_provider(provider)
            return provider, io
        provider, raw_io = make_provider()
        collector = provider_source._AuthenticatedCollector(provider, 3.0)
        observer = collector._io
        self.assertIs(observer._deadline_owner_v25, collector)
        foreign, unused_io = make_provider()
        other = provider_source._AuthenticatedCollector(foreign, 3.0)
        for proxy in (observer, provider_source._ObservationIo(provider, other)):
            with self.assertRaises(provider_source.LinuxProviderError) as caught: proxy.listdir('/proc')
            self.assertEqual('actor_unknown', caught.exception.code)
        self.assertEqual(0, raw_io.listdir.call_count)
        collector._deadline = 1.2  # Scoped owner-link test cap; no Snapshot or permission injected.
        with mock.patch.object(provider, '_private_pids', wraps=provider._private_pids) as private:
            self.assertEqual(['42'], observer.listdir('/proc'))
            private.assert_called_once_with(1.2)
        self.assertEqual(1, raw_io.listdir.call_count)
        status_io = provider_source._ObservationIo(provider)
        original_source = status.LinuxStatusSource(dict(provider.manifest.status_manifest), _io=status_io)
        original_reader = status.AuthenticatedStatusReader(dict(provider.manifest.status_manifest),
            original_source, _io=status_io)
        status_io._deadline_owner_v25 = original_reader
        with self.assertRaises(provider_source.LinuxProviderError) as caught: status_io.listdir('/proc')
        self.assertEqual('actor_unknown', caught.exception.code); self.assertEqual(1, raw_io.listdir.call_count)
        original_reader._deadline = 1.2
        self.assertEqual(['42'], status_io.listdir('/proc'))
        self.assertEqual(2, raw_io.listdir.call_count)
        wrong_proxy = provider_source._ObservationIo(provider, original_reader)
        with self.assertRaises(provider_source.LinuxProviderError) as caught: wrong_proxy.listdir('/proc')
        self.assertEqual('actor_unknown', caught.exception.code); self.assertEqual(2, raw_io.listdir.call_count)
        original_source._consumer = object()  # Wrong consumer remains rejected, not freshly read.
        with self.assertRaises(provider_source.LinuxProviderError) as caught: status_io.listdir('/proc')
        self.assertEqual('actor_unknown', caught.exception.code); self.assertEqual(2, raw_io.listdir.call_count)
        for invalid in (True, float('nan'), '1.2'):
            with self.assertRaises(provider_source.LinuxProviderError) as caught:
                provider._observe(_absolute_deadline=invalid)
            self.assertEqual('deadline', caught.exception.code)
        self.assertFalse(provider._proc_calls)
        self.assertTrue(all(not r._history for r in provider._store._resource_budget_v23._readers))

    def test_cap_validation_expiry_local_minimum_and_later_default_do_not_renew(self):
        for cap in (True, '1.2', float('nan'), float('inf'), -1, 1e12):
            with self.subTest(invalid=repr(cap)):
                clock, fs, store, reader = self.make_reader()
                with self.assertRaises(p.ProcReadError) as caught: reader.read_self(_absolute_deadline=cap)
                self.assertEqual('invalid_deadline', caught.exception.code)
                self.assertFalse(fs.operations); self.assertFalse(reader.operation_history)
        for cap in (0.9, 1.0):
            with self.subTest(expired=cap):
                clock, fs, store, reader = self.make_reader()
                value = reader.read_self(_absolute_deadline=cap)
                self.assertEqual(('unknown', 'deadline', 0), (value.kind, value.reason, value.file_count))
                self.assertFalse(fs.operations); self.assertTrue(reader.history_closed())
                self.assertEqual(cap, reader.operation_history[0].absolute_deadline)
        clock, fs, store, reader = self.make_reader(timeout=0.1)
        events = []
        def cross_local(unused, operation, path, count):
            events.append((operation, clock()))
            if operation == 'read' and clock() == 1.0: clock.value = 1.101
        fs.hook = cross_local
        value = reader.read_self(_absolute_deadline=9.0)
        self.assertEqual('deadline', value.reason); self.assertEqual(1.1, reader._deadline)
        self.assertEqual(9.0, reader.operation_history[0].absolute_deadline)
        self.assertFalse([(op, when) for op, when in events if op != 'close' and when >= 1.1])
        self.assertFalse(fs.live); self.assertTrue(reader.history_closed())
        clock.value, fs.hook = 2.0, None
        value = reader.read_self(_absolute_deadline=2.05)
        self.assertEqual('live_actor', value.kind); self.assertEqual(2.05, reader._deadline)
        clock.value = 3.0
        value = reader.read_self()  # None clears previous cap; it does not extend the old operation.
        self.assertEqual('live_actor', value.kind); self.assertEqual(3.1, reader._deadline)
        self.assertIsNone(reader.operation_history[-1].absolute_deadline)
        self.assertFalse(fs.live); self.assertTrue(reader.history_closed())
        self.assertEqual(0, store._resource_budget_v23.status()['active_producers'])

    def test_expiry_after_original_budget_acquisition_and_late_root_metadata_stop_first_io(self):
        clock, fs, store, reader = self.make_reader()
        budget, original = store._resource_budget_v23, store._resource_budget_v23._context
        def after_acquired():
            original()  # Actual original owner/mutex/epoch checks are not bypassed.
            clock.value = 1.201
        with mock.patch.object(budget, '_context', side_effect=after_acquired):
            value = reader.read_self(_absolute_deadline=1.2)
        self.assertEqual('deadline', value.reason); self.assertFalse(fs.operations)
        self.assertTrue(reader.history_closed()); self.assertEqual(1, len(reader.operation_history))
        self.assertEqual(0, budget.status()['active_producers'])
        # This is a synthetic clock crossing AFTER actual RLock acquisition,
        # not a claim about a real contended RLock's wall-clock wait.
        clock, fs, store, reader = self.make_reader()
        events = []
        def root_returns_late(unused, operation, path, count):
            events.append((operation, clock()))
            if operation == 'lstat' and path == '/proc': clock.value = 1.201
        fs.hook = root_returns_late
        value = reader.read_self(_absolute_deadline=1.2)
        self.assertEqual('deadline', value.reason)
        self.assertEqual([('lstat', 1.0)], events)  # In particular no late getpid.
        self.assertFalse(fs.opens); self.assertTrue(reader.history_closed())

    def test_all_three_actual_read_apis_stop_in_second_pass_and_close_original_fd(self):
        for api in ('self', 'actor', 'absence'):
            with self.subTest(api=api):
                clock, fs, store, reader = self.make_reader()
                first = reader.read_self()
                self.assertEqual('live_actor', first.kind)
                if api == 'absence': fs.remove_actor()
                events, crossed = [], [False]
                def second_pass_returns_late(unused, operation, path, count):
                    events.append((operation, clock(), path))
                    if reader._pass == 2 and operation == 'read' and not crossed[0]:
                        crossed[0] = True; clock.value = 1.201
                fs.hook = second_pass_returns_late
                value = (reader.read_self(_absolute_deadline=1.2) if api == 'self' else
                    reader.read_actor(first.actor.pid, first.actor, _absolute_deadline=1.2) if api == 'actor' else
                    reader.read_absence(first.actor, first.boot, _absolute_deadline=1.2))
                self.assertEqual(('unknown', 'deadline'), (value.kind, value.reason))
                self.assertTrue(crossed[0]); self.assertEqual(1.2, reader.operation_history[-1].absolute_deadline)
                self.assertFalse([(op, when) for op, when, path in events if when >= 1.2])
                self.assertEqual(value.file_count, value.closed_count)
                self.assertFalse(fs.live); self.assertTrue(reader.history_closed())
                self.assertTrue(all(ticket.ebadf_observed for generation in reader.operation_history
                    for ticket in generation.tickets))
                self.assertEqual(0, store._resource_budget_v23.status()['active_producers'])

    def test_proc_enumeration_rejects_original_bad_shape_before_private_child_io(self):
        provider_source = M['mta_client_linux_provider']
        cases = ({'123': None}, {'123'}, iter(('123',)), ['123', 456], ['123'] * 4097)
        for original in cases:
            with self.subTest(kind=type(original).__name__):
                io = types.SimpleNamespace(listdir=lambda path: original)
                provider = provider_source.LinuxClientInitProvider(_io=io, _clock=lambda: 1.0)
                private = provider._private_pids
                with mock.patch.object(provider, '_private_pids', wraps=private) as calls:
                    with self.assertRaises(provider_source.LinuxProviderError) as caught:
                        provider_source._ObservationIo(provider).listdir('/proc')
                    self.assertEqual('actor_unknown', caught.exception.code)
                    self.assertEqual(0, calls.call_count)

    def test_reused_status_and_collector_proc_stop_new_observation_io_at_outer_deadline(self):
        for scope in ('status_actor', 'collector_actor'):
            with self.subTest(scope=scope):
                clock, fs = Clock(), definitions.fs_fixture.FakeFs()
                store = s.DurableClientInitStore(definitions.fixture.old.TOKEN,
                    M['mta_p2p_client_init'].Identity(definitions.fixture.IDENTITY.candidate_sha),
                    _clock=clock)
                reader = p.ProcReader(_fs=fs, _clock=clock, timeout=3.0)
                store._resource_budget_v23.bind_reader(reader)
                first = reader.read_self()
                self.assertEqual('live_actor', first.kind)
                self.assertTrue(reader.history_closed())
                until, events, crossed = 1.2, [], [False]
                def advance_on_read(unused, operation, path, count):
                    events.append((operation, clock(), path))
                    if operation == 'read' and not crossed[0]:
                        crossed[0] = True
                        clock.value = until + 0.001  # This existing read returns late.
                fs.hook = advance_on_read
                manifest = definitions.fixture.manifest()
                if scope == 'status_actor':
                    source = status.LinuxStatusSource(dict(manifest.status_manifest),
                        _io=fs, _proc_reader=reader, _clock=clock)
                    files = status._ReadFiles(fs, clock, until, dict(manifest.status_manifest))
                    action = lambda: source._actor(files)
                else:
                    source = baseline.BaselineCollector(manifest.baseline_manifest,
                        _io=fs, _reader=reader, _clock=clock, timeout=3.0)
                    # Scoped primitive fixture only: this is collect's original
                    # absolute deadline, not an injected ready/network result.
                    source._deadline = until
                    action = lambda: source._proc()
                with self.assertRaises(baseline.BaselineError) as caught: action()
                self.assertEqual('deadline', caught.exception.code)
                observation_io = {'open', 'read', 'lstat', 'listdir', 'readlink', 'getpid'}
                late = [(operation, when) for operation, when, path in events
                    if operation in observation_io and when >= until]
                print('HOST_PROC_OUTER_DEADLINE', scope, 'late_observation_io', len(late),
                    'known_open', len(fs.opens), 'closed', len(fs.closed))
                self.assertTrue(crossed[0])
                self.assertEqual([], late, 'new observation IO started after the original outer deadline')
                self.assertFalse(fs.live)
                self.assertEqual(len(fs.opens), len(fs.closed))
                self.assertEqual(2, len(reader.operation_history))
                self.assertIs(reader.operation_history[0].observation, first)
                self.assertTrue(reader.history_closed())  # Local close only, not source authentication.
                self.assertEqual(0, store._resource_budget_v23.status()['active_producers'])
                if scope == 'status_actor':
                    self.assertFalse(source._issued)
                    self.assertTrue(source._actor_calls[-1]['unknown'])


if __name__ == '__main__': unittest.main()
