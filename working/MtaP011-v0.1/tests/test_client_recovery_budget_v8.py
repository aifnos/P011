"""SOURCE/HOST FakeIO only: recovery total is not an RF authorization."""
import ast
import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'runtime'))
sys.path.insert(0, str(BASE / 'tests'))
import mta_client_coordination as coord
import mta_client_files as files
import mta_client_proc as proc
import mta_client_journal_codec as codec
import mta_p2p_client_init as core
import mta_client_process_owner as owner
from test_durable_client_store import StoreIo
from test_client_pending import Reader
from test_client_files import TOKEN, TARGET, PENDING, RUN
from test_client_journal_codec import baseline, IDENTITY, OWNED
from test_client_store_fresh_v5 import state_snapshot
from test_client_owned_origin_v4 import manifest, Io, Proc
from test_client_linux_provider import Collector

DIRECTORY = BASE / 'candidate/client-recovery-budget-v8/runtime'


def load(name):
    spec = importlib.util.spec_from_file_location(name, str(DIRECTORY / (name + '.py')))
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


with mock.patch.dict(sys.modules):
    marker_module = load('mta_client_pending')
    store_module = load('mta_client_store')
    provider_module = load('mta_client_linux_provider')
s, m, p = store_module, marker_module, provider_module


class Producer(object):
    """Synthetic exact registry. No kernel/provider authentication claim."""
    def __init__(self, io, seconds=4.1, auth_seconds=0.0):
        self.io, self.seconds, self.auth_seconds = io, seconds, auth_seconds
        self.issued, self.authenticated, self.clocks = [], [], []
        self.hook, self.fail, self.reuse = None, None, False

    def read_prior(self, store, locks, request, deadline):
        self.clocks.append((deadline - self.io.clock.value, store._io_deadline,
            store._coordination._deadline, store._files._deadline,
            None if store._marker is None else store._marker._deadline))
        self.io.clock.value += self.seconds
        if self.fail: raise self.fail
        value = state_snapshot('S')
        self.issued.append((store, locks, request, value, deadline))
        if self.hook: self.hook(store, len(self.issued))
        return value

    def read_restore(self, store, locks, request, deadline):
        snap = self.read_prior(store, locks, request, deadline)
        value = (snap, core.CloseProof(2, (True, True), (True, True)))
        if self.reuse and len(self.issued) > 1: value = self.issued[-2][3]
        self.issued[-1] = (store, locks, request, value, deadline)
        return value

    def authenticate_prior(self, store, locks, request, value, deadline):
        self.io.clock.value += self.auth_seconds
        if not any(a is store and b is locks and c is request and d is value and e == deadline
                for a, b, c, d, e in self.issued): raise ValueError('synthetic unissued')
        self.authenticated.append(value)
        return None
    authenticate_restore = authenticate_prior


class RecoveryBudgetTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(sys.modules, {'mta_client_store': s, 'mta_client_pending': m})
        patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(p.phases, 'stores', s)
        patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(p.phases.launches, 'store_module', s)
        patcher.start(); self.addCleanup(patcher.stop)
        for cls in (coord._LinuxIo, files._LinuxIo, m._LinuxIo):
            for name in ('validate', 'open_root', 'open_at', 'fstat', 'stat_at', 'close',
                    'read', 'write', 'fsync', 'seek_start', 'flock', 'rename_at', 'unlink_at'):
                if hasattr(cls, name):
                    patcher = mock.patch.object(cls, name, side_effect=AssertionError('actual OS forbidden'))
                    patcher.start(); self.addCleanup(patcher.stop)
        for name in ('ctypes.CDLL', 'socket.socket', 'subprocess.Popen', 'os.kill', 'os.waitpid'):
            patcher = mock.patch(name, side_effect=AssertionError('actual OS forbidden'), create=True)
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(proc.ProcReader, 'read_self', side_effect=AssertionError('actual proc forbidden'))
        patcher.start(); self.addCleanup(patcher.stop)
        p._OWNERS[:] = []
        self.addCleanup(lambda: p._OWNERS.__setitem__(slice(None), []))

    def make(self, io=None, prior=False, restore=True):
        io = io or StoreIo()
        reader = Reader(); reader.boot = baseline().boot
        producer = Producer(io)
        store = s.DurableClientInitStore(TOKEN, IDENTITY, _coordination_io=io, _files_io=io,
            _pending_io=io, _proc_reader=reader, _clock=io.clock,
            _prior_reader=producer if prior else None, _restore_reader=producer if restore else None)
        self.addCleanup(store.close)
        locks = store.acquire(IDENTITY, 3)
        return store, io, locks, producer

    def cleaned(self, **kwargs):
        store, io, locks, producer = self.make(**kwargs)
        record = store.commit(locks, core.Journal(IDENTITY, 'prepared', baseline(), 10))
        record = store.commit(locks, record.replace(stage='cleanup_intent'))
        record = store.commit(locks, record.replace(stage='cleanup_verified'))
        return store, io, locks, producer, record

    def test_prior_fresh_four_seconds_plus_auth_is_not_disk_three_seconds(self):
        store, io, locks, producer = self.make(prior=True)
        producer.auth_seconds = .4
        before = io.clock.value
        self.assertTrue(store.prior_clear(locks, baseline(), 20))
        self.assertAlmostEqual(4.5, io.clock.value - before)
        self.assertEqual(5, producer.clocks[0][0])
        self.assertEqual((None, None, None), producer.clocks[0][2:])
        self.assertLessEqual(store._io_deadline - io.clock.value, 3)
        self.assertEqual(1, len(producer.authenticated))
        self.assertNotIn(TARGET, io.nodes)

    def test_prior_start_deadline_and_combined_fresh_auth_five_seconds_remain_limits(self):
        for deadline, duration, auth in ((3, 3.1, 0), (20, 4.9, .2), (60, 0, 0)):
            store, io, locks, producer = self.make(prior=True)
            producer.seconds, producer.auth_seconds = duration, auth
            with self.assertRaises(s.DurableStoreError): store.prior_clear(locks, baseline(), deadline)
            self.assertNotIn(TARGET, io.nodes)

    def test_three_actual_fresh_reads_finish_after_rf_ttl_without_extending_record(self):
        store, io, locks, producer, record = self.cleaned()
        disk_bounds = []
        def observe(io, operation, path, count):
            if operation == 'unlink':
                disk_bounds.append(tuple(x - io.clock.value for x in (store._io_deadline,
                    store._coordination._deadline, store._files._deadline, store._marker._deadline)))
        io.hook = observe
        receipt = store.finish(locks, record, True, 60)
        self.assertTrue(receipt.complete)
        self.assertEqual(3, len(producer.issued)); self.assertEqual(3, len(producer.authenticated))
        self.assertGreater(io.clock.value, record.deadline)
        self.assertEqual(10, receipt.record.deadline)
        self.assertEqual(1, io.counts.get(('unlink', PENDING)))
        self.assertEqual(1, len(disk_bounds)); self.assertTrue(all(0 < t <= 3 for t in disk_bounds[0]))
        self.assertTrue(store.authenticate_finish(locks, record, receipt, 60))
        self.assertTrue(store.closed_locks(locks, io.clock.value + 3).complete())
        for row in store._files._inventory + store._coordination._inventory:
            self.assertTrue(store._fd_closed(row))
        self.assertEqual(3, len(producer.clocks))
        self.assertTrue(all(c[0] <= 5 and c[2:] == (None, None, None) for c in producer.clocks))
        self.assertFalse(store.status()['production_provider'])

    def test_third_callback_postfresh_marker_change_zero_unlink(self):
        store, io, locks, producer, record = self.cleaned()
        def change(obj, call):
            if call == 3: io.nodes[PENDING].data += b' '
        producer.hook = change
        receipt = store.finish(locks, record, True, 60)
        self.assertFalse(receipt.complete); self.assertTrue(receipt.terminal_durable)
        self.assertEqual(3, len(producer.issued)); self.assertIn(PENDING, io.nodes)
        self.assertEqual(0, io.counts.get(('unlink', PENDING), 0))
        self.assertTrue(store._marker._clear_sealed)

    def test_short_unlink_segment_expiry_does_not_retry_or_claim_durable_absence(self):
        store, io, locks, producer, record = self.cleaned()
        def slow(io, operation, path, count):
            if operation == 'unlink': io.clock.value += 3.1
        io.hook = slow
        receipt = store.finish(locks, record, True, 60)
        self.assertFalse(receipt.complete)
        self.assertNotEqual('verified', receipt.clear_durability)
        self.assertEqual(1, io.counts.get(('unlink', PENDING), 0))
        self.assertNotIn(PENDING, io.nodes)  # Physical syscall is separate from durable proof.

    def test_total_deadline_expires_no_new_fresh_slice_or_unlink(self):
        store, io, locks, producer, record = self.cleaned()
        receipt = store.finish(locks, record, True, 8)
        self.assertFalse(receipt.complete); self.assertIn(PENDING, io.nodes)
        self.assertEqual(2, len(producer.issued)); self.assertEqual(1, len(producer.authenticated))
        self.assertEqual(0, io.counts.get(('unlink', PENDING), 0))
        self.assertEqual(8, store._finish_deadline)

    def test_failed_producer_restores_all_four_deadline_contexts_and_retains_owner(self):
        store, io, locks, producer, record = self.cleaned()
        before = (store._io_deadline, store._coordination._deadline, store._files._deadline, store._marker._deadline)
        producer.fail = ValueError('private reader failure')
        with self.assertRaises(ValueError): store._fresh_restore(locks, record, 60)
        after = (store._io_deadline, store._coordination._deadline, store._files._deadline, store._marker._deadline)
        self.assertEqual(before, after); self.assertIs(producer, store._restore_reader)
        self.assertIn(PENDING, io.nodes)

    def test_delayed_reused_or_boolean_auth_cannot_clear(self):
        store, io, locks, producer, record = self.cleaned(); producer.reuse = True
        receipt = store.finish(locks, record, True, 60)
        self.assertFalse(receipt.complete); self.assertIn(PENDING, io.nodes)
        self.assertEqual(1, len(producer.authenticated))
        obj, io, locks, producer, record = self.cleaned()
        producer.authenticate_restore = lambda *args: True
        self.assertFalse(obj.finish(locks, record, True, 60).complete)
        self.assertEqual(0, io.counts.get(('unlink', PENDING), 0))

    def test_record_cas_and_default_missing_restore_are_unchanged(self):
        store, io, locks, producer, record = self.cleaned(restore=False)
        result = store.finish(locks, record, True, 60)
        self.assertFalse(result.complete); self.assertFalse(result.terminal_durable)
        self.assertIn(PENDING, io.nodes)
        obj, io, locks, _ = self.make()
        record = obj.commit(locks, core.Journal(IDENTITY, 'prepared', baseline(), 10))
        with self.assertRaises(s.DurableStoreError):
            obj.commit(locks, record.replace(stage='cleanup_intent', baseline=state_snapshot('S')))
        self.assertEqual(10, codec.decode_journal(io.nodes[TARGET].data).deadline)

    def test_provider_restore_real_components_keep_nine_full_reads_and_eight_child_slice(self):
        store, io, locks, producer = self.make(io=Io(), restore=False)
        provider = p.LinuxClientInitProvider(manifest(p), _io=io, _clock=io.clock,
            _proc_factory=lambda **kw: Proc(io, **kw), _collector_factory=Collector)
        direct = owner.DirectChildOwner(_clock=io.clock)
        bridge = p.LinuxDirectChildLaunchBridge(store, direct, provider.specs(), provider)
        lease = p.LinuxClientInitLease(provider, store, IDENTITY, io.clock, bridge)
        provider.attach(store, direct, bridge, lease)
        record = store.commit(locks, core.Journal(IDENTITY, 'prepared', baseline(), 10))
        tickets, actors = {}, {}
        for role, pid in (('watchdog', 200), ('controller', 300)):
            launch = bridge.specs[role]
            tickets[role] = core.Ticket(('1' if role == 'watchdog' else '2') * 32,
                role, baseline().boot, launch.exe, launch.argv_sha)
            actors[role] = core.Actor(pid, 30, launch.exe, launch.argv_sha, ((pid, 30, 'S'),))
        interface = core.InterfaceTicket(baseline().boot, 0, OWNED.name, 1, 900)
        for change in (dict(stage='watchdog_intent', watchdog_ticket=tickets['watchdog']),
                dict(stage='watchdog_saved', watchdog=actors['watchdog']),
                dict(stage='interface_intent', interface_ticket=interface),
                dict(stage='interface_owned', owned=OWNED),
                dict(stage='controller_intent', controller_ticket=tickets['controller']),
                dict(stage='controller_saved', controller=actors['controller']),
                dict(stage='client_init_ready', ready=True)):
            record = store.commit(locks, record.replace(**change))
        lease.record, lease.locks = record, locks
        provider._self, provider._boot, provider._baseline_record = store._proc_reader.actor, baseline().boot, baseline()
        provider._owned = OWNED
        b = baseline()
        provider.fake_snapshot = core.Snapshot(b.boot, b.stock_hashes, b.stock_actors, b.station,
            b.station_state_sha, b.station_frequency, b.interfaces + (OWNED,), b.ipv4,
            b.ipv6_addresses, b.ipv6_routes, b.station_completed)
        provider._kernel.interfaces = lambda deadline: provider.fake_snapshot.interfaces
        deletes = []
        def delete(family, command, attributes, flags, deadline):
            self.assertEqual(8, command); deletes.append(command)
            provider.fake_snapshot = baseline(); return []
        provider._kernel.family, provider._kernel.request = 30, delete
        store.active_return(locks, record)
        calls, child = [], []
        real_snapshot = provider.snapshot
        def delayed(deadline):
            calls.append(deadline - io.clock.value)
            value = real_snapshot(deadline); io.clock.value += 4.1
            return value
        provider.snapshot = delayed
        # Explicitly synthetic child closure; no actual forks/waits/radio.
        bridge.cleanup = lambda exact, deadline: child.append(deadline - io.clock.value) or True
        bridge.verify_closed = lambda: True
        store._restore_reader = provider
        result = lease.restore()
        self.assertTrue(result['cleanup_complete'])
        self.assertEqual(9, len(calls)); self.assertEqual([8], deletes)
        self.assertEqual([8], child); self.assertTrue(all(0 < value <= 5 for value in calls))
        self.assertEqual(10, lease.record.deadline)
        self.assertFalse(result['production_provider']); self.assertFalse(result['send_available'])

    def test_restoration_context_caps_default_current_and_cas_before_and_after_total(self):
        store, io, locks, _ = self.make()
        record = store.commit(locks, core.Journal(IDENTITY, 'prepared', baseline(), 10))
        store._recovery_deadline = 1.5
        io.clock.value = 1.4
        actual = store.current(locks)
        self.assertLessEqual(store._io_deadline, 1.5)
        before = list(io.ops)
        io.clock.value = 1.5
        with self.assertRaises(s.DurableStoreError):
            store.commit(locks, actual.replace(stage='cleanup_intent'))
        self.assertEqual(before, io.ops)
        with self.assertRaises(s.DurableStoreError): store.current(locks)
        self.assertEqual(10, record.deadline)

    def test_source_originals_caps_and_start_unchanged_python35(self):
        source_pins = ((BASE / 'candidate/client-owned-origin-v4/runtime/mta_client_linux_provider.py',
                'a8ca35f57841bf75b9ea53120404a395e2ad446cb2859a16a6c5c225efbb5491'),
            (BASE / 'candidate/client-store-fresh-v5/runtime/mta_client_store.py',
                'bbe71e419260a2f83e266a5b9fb401e9dc5e82a78c892ea4daad77f0bb8b3df3'),
            (BASE / 'runtime/mta_client_pending.py',
                'edd6553b847db6dc8e5d2be48256b8e3ee706adca25cbda316bcf28f357ff7cf'))
        for path, expected in source_pins: self.assertEqual(expected, hashlib.sha256(path.read_bytes()).hexdigest())
        for path in [DIRECTORY / (name + '.py') for name in
                ('mta_client_linux_provider', 'mta_client_store', 'mta_client_pending')] + [Path(__file__)]:
            tree = ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 5))
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        old_tree = ast.parse(source_pins[0][0].read_text(encoding='utf-8'))
        new_tree = ast.parse((DIRECTORY / 'mta_client_linux_provider.py').read_text(encoding='utf-8'))
        self.assertEqual(ast.dump(old_tree.body[-1]), ast.dump(new_tree.body[-1]))  # assemble unchanged
        old_store = ast.parse(source_pins[1][0].read_text(encoding='utf-8'))
        new_store = ast.parse((DIRECTORY / 'mta_client_store.py').read_text(encoding='utf-8'))
        old = next(v for v in old_store.body if isinstance(v, ast.ClassDef) and v.name == 'DurableClientInitStore')
        new = next(v for v in new_store.body if isinstance(v, ast.ClassDef) and v.name == old.name)
        for name in ('_transition', 'commit', '_publish', 'acquire', 'closed_locks'):
            self.assertEqual(ast.dump(next(v for v in old.body if getattr(v, 'name', None) == name)),
                ast.dump(next(v for v in new.body if getattr(v, 'name', None) == name)))


if __name__ == '__main__': unittest.main()
