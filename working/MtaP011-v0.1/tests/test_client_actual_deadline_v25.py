"""Two NEW affected HOST methods; no old method, device or wall-time claim.

Reuse only frozen v25 collector fixture definitions, actual PC stock bytes,
and ROOT's pinned v25 four-replacement private domain. Synthetic filesystem
hooks advance clock. Actual collectors, STATUS consumers, original private
controller issuance, original resource/unknown gates are not substituted.
"""
from contextlib import ExitStack
import hashlib
import importlib
from pathlib import Path
import sys
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
FIXTURE_SHA = 'd3285398a5a6eb6f0b48826dbcfce0281ad97be41a7a1723d7bb0060b346f657'
DOMAIN_DEFINITIONS_SHA = '2852349973865d3a2b09bbd4ac51862d651429a1e31bbcb363e125669b0a61b4'
OBSERVATION_IO = frozenset(('open', 'read', 'lstat', 'listdir', 'readlink', 'getpid', 'stat'))


def load_definitions():
    sys.path.insert(0, str(BASE / 'tests'))
    path = BASE / 'tests/test_client_actual_collector_v25.py'
    if hashlib.sha256(path.read_bytes()).hexdigest() != FIXTURE_SHA:
        raise ValueError('frozen collector fixture drift')
    fixture = importlib.import_module('test_client_actual_collector_v25')
    full, packets = fixture.dependencies()
    if hashlib.sha256((BASE / 'tests/test_client_proc_absolute_deadline_v25.py').read_bytes()).hexdigest() != DOMAIN_DEFINITIONS_SHA:
        raise ValueError('ROOT fixed domain definitions drift')
    scoped = importlib.import_module('test_client_proc_absolute_deadline_v25')
    # ROOT domain verifies old 29-row manifest and four new fixed source pins;
    # never invoke its prior/new TestCase methods or mutate any manifest rows.
    modules = scoped.domain()
    if type(modules) is tuple: modules = modules[0]
    return fixture, full, packets, modules


def prepare(modules, fixture, full, packets):
    values = fixture.make_fixture(modules, full, packets)
    lease, provider, store, owner, bridge, io, fs, kernel, net, clock = values
    locks = store.acquire(provider.manifest.identity, clock() + 3)
    child = owner.register(provider.specs()[1], locks._device.fd, clock() + 10)
    owner.launch(child)
    owner.release(child, lambda original, actor:
        modules['mta_client_process_owner'].PersistReceipt(original, actor))
    owner.resolve(child)
    if child.postexec is None or child.unknown or not child.released:
        raise AssertionError('HOST actual private child not issued')
    fs.files['/proc/' + str(child.pid) + '/comm'] = b'wpa_supplicant\n'
    provider.executor(clock() + 5)
    return values, child


class Trace:
    """Only explicit FakeFS hooks, never wrap actual producer methods."""
    def __init__(self, values, mode=None):
        self.lease, self.provider, self.store, self.owner, self.bridge, self.io, self.fs, self.kernel, self.net, self.clock = values
        self.mode, self.events, self.generations, self.crossed = mode, [], {}, False
        self.until, self.fault_generation, self.enabled = None, None, True
        self.originals = []
        for surface, names in ((self.io, ('open', 'read', 'fstat', 'close', 'stat', 'listdir', 'readlink')),
                (self.fs, ('lstat', 'open', 'read', 'fstat', 'close', 'listdir', 'readlink', 'getpid'))):
            for name in names:
                original = getattr(surface, name)
                self.originals.append((surface, name, original))
                setattr(surface, name, self.wrap(surface, name, original))

    def current(self):
        collector = None if not self.provider._collectors else self.provider._collectors[-1]['reader']
        status = None
        if collector is not None:
            for row in reversed(collector.status_readers):
                reader = row['reader']
                if reader is not None and not reader._ended:
                    status = reader; break
        active = [reader for reader in self.store._resource_budget_v23._readers
            if reader._current_generation is not None]
        if len(active) > 1: raise AssertionError('HOST multiple actual Proc producers')
        reader = active[0] if active else None
        generation = None if reader is None else reader._current_generation
        private = reader is not None and any(row['reader'] is reader for row in self.provider._proc_calls)
        if status is not None:
            until = status._deadline
            scope = 'private_status' if private else 'status_actor'
        elif collector is not None:
            until, scope = collector._deadline, 'private_collector' if private else 'collector_actor'
        else:
            until, scope = self.provider._deadline, 'provider'
        return generation, until, scope, status

    def wrap(self, surface, operation, original):
        def call(*args, **kwargs):
            if not self.enabled: return original(*args, **kwargs)
            generation, until, scope, status = self.current()
            self.events.append((operation, self.clock(), until, scope))
            if generation is not None:
                previous = self.generations.setdefault(id(generation), (generation, until, scope))
                if previous != (generation, until, scope):
                    raise AssertionError('HOST actual generation changed enclosing scope')
            returned = original(*args, **kwargs)
            fault = status is not None and not self.crossed and (
                self.mode == 'enumeration' and surface is self.io and operation == 'listdir' and args == ('/proc',) or
                self.mode == 'private_read' and surface is self.fs and operation == 'read' and scope == 'private_status')
            if fault:
                self.crossed, self.until, self.fault_generation = True, until, generation
                self.clock.value = until + 0.001  # Existing synchronous syscall returns late.
            elif self.mode is None:
                self.clock.value += 0.000001
            return returned
        return call

    def disable(self):
        self.enabled = False
        for surface, name, original in reversed(self.originals): setattr(surface, name, original)


class ActualDeadlineV25Tests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        # Expanded actual OS observation tripwires are HOST-only, not a claim
        # that a thread or syscall can be forcibly interrupted on P011.
        for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
                'ctypes.CDLL', 'os.open', 'os.read', 'os.close', 'os.fstat',
                'os.lstat', 'os.listdir', 'os.readlink', 'os.getpid', 'os.fork',
                'os.execve', 'os.kill', 'os.waitpid', 'os.system',
                'threading.Thread.start', 'time.sleep'):
            self.stack.enter_context(mock.patch(name, side_effect=AssertionError('actual OS forbidden'), create=True))

    def make(self):
        fixture, full, packets, modules = load_definitions()
        p = modules['mta_client_linux_provider']; p._OWNERS[:] = []
        self.addCleanup(lambda: p._OWNERS.__setitem__(slice(None), []))
        values, child = prepare(modules, fixture, full, packets)
        self.assertIsNone(values[0].record); self.assertFalse(values[0].handles)
        self.assertFalse(values[4]._operations)
        return modules, values, child

    def test_microstep_actual_collector_status_and_private_fresh_keep_original_absolute_caps(self):
        modules, values, child = self.make()
        lease, provider, store, owner, bridge, io, fs, kernel, net, clock = values
        trace = Trace(values)
        self.addCleanup(trace.disable)
        snapshot = provider.snapshot(clock() + 5)
        collector = provider._collectors[-1]['reader']
        self.assertEqual(2, len(collector._rounds)); self.assertEqual(2, len(collector.status_readers))
        self.assertEqual(collector._rounds[0].key(), snapshot.key())
        for generation in collector._reader.operation_history:
            self.assertEqual(collector._deadline, generation.absolute_deadline)
        for row in collector.status_readers:
            status, source = row['reader'], row['source']
            self.assertEqual(8, len(source._reader.operation_history))
            self.assertEqual(2, len(source._issued)); self.assertEqual(2, len(status._sources))
            self.assertIs(source._io, status._io)
            self.assertIs(object.__getattribute__(source._io, '_deadline_owner_v25'), status)
            for generation in source._reader.operation_history:
                self.assertEqual(status._deadline, generation.absolute_deadline)
            self.assertLess(status._deadline, collector._deadline)
            self.assertEqual([b'STATUS'], status._socket.sent)
            self.assertEqual(1, status._socket.received); self.assertEqual(1, status._socket.close_count)
        scopes = [scope for generation, until, scope in trace.generations.values()]
        self.assertGreaterEqual(scopes.count('private_status'), 4)
        self.assertGreaterEqual(scopes.count('private_collector'), 2)
        for generation, until, scope in trace.generations.values():
            self.assertEqual(until, generation.absolute_deadline)
            if scope == 'private_status': self.assertLess(until, provider._deadline)
        self.assertFalse(any(operation in OBSERVATION_IO and when >= until
            for operation, when, until, scope in trace.events))
        self.assertGreater(clock(), 1.0); self.assertLess(clock(), collector._deadline)
        self.assertTrue(all(reader.history_closed() for reader in store._resource_budget_v23._readers))
        trace.disable()
        net.stopped.add(child.pid)
        self.assertTrue(owner.wait_reap(child, 1)); self.assertTrue(owner.fresh_exit(child))
        self.assertTrue(owner.close_inventory(child)); store.close()
        self.assertFalse(io.handles); self.assertFalse(kernel.live)
        self.assertFalse(provider._create_requested); self.assertIsNone(lease.record)

    def test_private_controller_expiry_at_enumeration_return_or_first_read_starts_no_new_io(self):
        for mode in ('enumeration', 'private_read'):
            with self.subTest(mode=mode):
                modules, values, child = self.make()
                lease, provider, store, owner, bridge, io, fs, kernel, net, clock = values
                # Parent-side child FD inventory can close while its issued
                # live process identity remains. Do this BEFORE expiry so no
                # after-expiry owner read is needed to sign local FD closure.
                self.assertTrue(owner.close_inventory(child)); self.assertFalse(kernel.live)
                trace = Trace(values, mode); self.addCleanup(trace.disable)
                with self.assertRaises(modules['mta_client_baseline'].BaselineError) as caught:
                    provider.snapshot(clock() + 5)
                self.assertIn(caught.exception.code, modules['mta_client_baseline']._CODES)
                self.assertTrue(trace.crossed)
                late = [(operation, when) for operation, when, unused, scope in trace.events
                    if operation in OBSERVATION_IO and when >= trace.until]
                self.assertEqual([], late, 'new observation IO after original STATUS until')
                collector = provider._collectors[-1]['reader']
                self.assertFalse(collector.status()['read_success'])
                self.assertEqual(1, len(collector.status_readers))
                status = collector.status_readers[0]['reader']
                self.assertFalse(status.status()['read_success']); self.assertFalse(status._result)
                self.assertIsNone(status._socket)  # First source failed; no STATUS query at all.
                self.assertTrue(all(row['closed'] and not row['unknown'] for row in collector._tickets))
                self.assertTrue(all(row['closed'] and not row['unknown']
                    for files in collector.status_readers[0]['source']._files for row in files._tickets))
                if mode == 'private_read':
                    self.assertIsNotNone(trace.fault_generation)
                    self.assertEqual(trace.until, trace.fault_generation.absolute_deadline)
                    self.assertTrue(trace.fault_generation.tickets)
                    self.assertTrue(all(trace.fault_generation.reader.closed_open_ticket(ticket) and
                        ticket.ebadf_observed and not ticket.unknown
                        for ticket in trace.fault_generation.tickets))
                else:
                    self.assertIsNone(trace.fault_generation)
                    self.assertFalse(any(scope == 'private_status'
                        for generation, until, scope in trace.generations.values()))
                self.assertTrue(provider._collectors[-1]['unknown'])
                self.assertTrue(store._resource_budget_v23.status()['resource_pending'])
                self.assertEqual(0, store._resource_budget_v23.status()['active_producers'])
                # Remain fail-closed and retain unknown consumer originals.
                # No process reap/restoration proof, no network renewal.
                trace.disable(); store.close()
                self.assertFalse(io.handles); self.assertFalse(kernel.live)
                self.assertTrue(store._resource_budget_v23.status()['resource_pending'])
                self.assertIsNone(lease.record); self.assertFalse(lease.handles)
                self.assertFalse(provider._create_requested)


if __name__ == '__main__': unittest.main()
