"""Isolated v5 Store; real components over HOST FakeIO, no OS/RF evidence."""
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
import mta_client_store as original
import mta_client_coordination as coordination
import mta_client_files as files
import mta_client_pending as pending
import mta_client_proc as proc
import mta_client_journal_codec as codec
import mta_p2p_client_init as core
import mta_ip as ip
from test_durable_client_store import StoreIo
from test_client_files import TOKEN, TARGET, PENDING
from test_client_pending import Reader
from test_client_journal_codec import baseline, IDENTITY

ORIGINAL_SHA = 'c6d4c8b7fda8370be83efafe61bfad4a4680ef7a8edba51a89f539c6868594cd'
PATH = BASE / 'candidate/client-store-fresh-v5/runtime/mta_client_store.py'
spec = importlib.util.spec_from_file_location('client_store_fresh_v5', str(PATH))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def snapshot(source=None, **changes):
    source = source if source is not None else baseline()
    keys = ('boot', 'stock_hashes', 'stock_actors', 'station', 'station_state_sha',
        'station_frequency', 'interfaces', 'ipv4', 'ipv6_addresses', 'ipv6_routes', 'station_completed')
    values = dict((key, getattr(source, key)) for key in keys)
    values.update(changes)
    return core.Snapshot(*(values[key] for key in keys))


def state_snapshot(state, source=None):
    source = source if source is not None else baseline()
    actors = tuple(core.Actor(a.pid, a.start, a.exe, a.argv_sha,
        tuple((pid, start, state) for pid, start, old in a.tasks)) for a in source.stock_actors)
    return snapshot(source, stock_actors=actors)


def changed_actor(**changes):
    source = baseline()
    a = source.stock_actors[0]
    values = dict(pid=a.pid, start=a.start, exe=a.exe, argv_sha=a.argv_sha, tasks=a.tasks)
    values.update(changes)
    actors = (core.Actor(**values),) + source.stock_actors[1:]
    return snapshot(source, stock_actors=actors)


class PriorProducer(object):
    """Synthetic issuance registry, never a kernel/manifest admission proof."""
    def __init__(self, factory):
        self.factory, self.issued, self.authenticated = factory, [], []
        self.auth_mode = 'issued'

    def read_prior(self, store, locks, requested, deadline):
        value = self.factory()
        self.issued.append((store, locks, requested, value))
        return value

    def authenticate_prior(self, store, locks, requested, value, deadline):
        if self.auth_mode == 'bool': return True
        if self.auth_mode == 'reject': raise ValueError('synthetic_unissued')
        if not any(a is store and b is locks and c is requested and d is value for a, b, c, d in self.issued):
            raise ValueError('synthetic_unissued')
        self.authenticated.append(value)
        return None


class RestoreProducer(PriorProducer):
    def __init__(self, factory):
        PriorProducer.__init__(self, factory)
        self.reuse = None

    def read_restore(self, store, locks, requested, deadline):
        snap = self.factory()
        proof = core.CloseProof(2, (True, True), (True, True))
        value = (snap, proof)
        if self.issued and self.reuse == 'tuple': value = self.issued[-1][3]
        elif self.issued and self.reuse == 'snapshot': value = (self.issued[-1][3][0], proof)
        elif self.issued and self.reuse == 'proof': value = (snap, self.issued[-1][3][1])
        self.issued.append((store, locks, requested, value))
        return value

    def authenticate_restore(self, store, locks, requested, value, deadline):
        return self.authenticate_prior(store, locks, requested, value, deadline)


class FreshStoreTests(unittest.TestCase):
    def setUp(self):
        # Isolated deployment resolves Pending's exact Store import to this copy.
        patcher = mock.patch.dict(sys.modules, {'mta_client_store': s})
        patcher.start(); self.addCleanup(patcher.stop)
        for cls in (coordination._LinuxIo, files._LinuxIo, pending._LinuxIo):
            for name in ('validate', 'open_root', 'open_at', 'fstat', 'stat_at', 'close',
                    'read', 'write', 'fsync', 'seek_start', 'flock', 'rename_at', 'unlink_at'):
                if hasattr(cls, name):
                    patcher = mock.patch.object(cls, name, side_effect=AssertionError('actual OS forbidden'))
                    patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket', 'subprocess.Popen'):
            patcher = mock.patch(target, side_effect=AssertionError('actual OS forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(proc.ProcReader, 'read_self', side_effect=AssertionError('actual proc forbidden'))
        patcher.start(); self.addCleanup(patcher.stop)

    def make(self, prior=None, restore=None):
        io, reader = StoreIo(), Reader()
        reader.boot = baseline().boot
        store = s.DurableClientInitStore(TOKEN, IDENTITY, _coordination_io=io,
            _files_io=io, _pending_io=io, _proc_reader=reader, _clock=io.clock,
            _prior_reader=prior, _restore_reader=restore)
        self.addCleanup(store.close)
        return store, io, store.acquire(IDENTITY, 3.0)

    def prepared(self, restore=None):
        store, io, locks = self.make(restore=restore)
        current = store.commit(locks, core.Journal(IDENTITY, 'prepared', baseline(), 10.0))
        return store, io, locks, current

    def cleaned(self, restore):
        store, io, locks, current = self.prepared(restore)
        current = store.commit(locks, current.replace(stage='cleanup_intent'))
        current = store.commit(locks, current.replace(stage='cleanup_verified'))
        return store, io, locks, current

    def rejection(self, call, code):
        with self.assertRaises(s.DurableStoreError) as caught: call()
        self.assertEqual(code, caught.exception.code)

    def test_prior_fresh_r_to_s_accepted_without_changing_raw_observation(self):
        value = state_snapshot('S')
        producer = PriorProducer(lambda: value)
        store, io, locks = self.make(prior=producer)
        requested = baseline()
        self.assertFalse(original._same_baseline(value, requested))
        self.assertTrue(store.prior_clear(locks, requested, 3.0))
        self.assertIs(value, store._prior_observations[-1])
        self.assertEqual([value], producer.authenticated)
        self.assertEqual('S', value.stock_actors[0].tasks[0][2])
        self.assertEqual('R', requested.stock_actors[0].tasks[0][2])
        self.assertNotIn(TARGET, io.nodes)

    def test_restore_fresh_live_states_finish_authenticates_each_issued_observation(self):
        states = iter(('S', 'R', 'S'))
        producer = RestoreProducer(lambda: state_snapshot(next(states)))
        store, io, locks, current = self.cleaned(producer)
        original_tasks = tuple(a.tasks for a in current.baseline.stock_actors)
        result = store.finish(locks, current, True, 3.0)
        self.assertTrue(result.complete)
        self.assertEqual(3, len(producer.authenticated))
        self.assertNotIn(PENDING, io.nodes)
        self.assertEqual(original_tasks, tuple(a.tasks for a in result.record.baseline.stock_actors))
        decoded = codec.decode_journal(io.nodes[TARGET].data)
        self.assertTrue(core._same_journal(decoded, result.record))
        self.assertEqual(original_tasks, tuple(a.tasks for a in decoded.baseline.stock_actors))
        self.assertFalse(store.status()['production_provider'])

    def test_prior_and_restore_reject_stable_actor_identity_or_task_set_changes(self):
        values = (
            changed_actor(argv_sha='0' * 64),
            changed_actor(start=102, tasks=((11, 102, 'S'), (111, 101, 'D'))),
            changed_actor(tasks=((11, 100, 'S'), (111, 102, 'D'))),
            changed_actor(tasks=((11, 100, 'S'),)),
            changed_actor(tasks=((11, 100, 'S'), (111, 101, 'D'), (112, 102, 'S'))),
        )
        for value in values:
            with self.subTest(key=value.stock_actors[0].key()):
                producer = PriorProducer(lambda value=value: value)
                store, _, locks = self.make(prior=producer)
                self.rejection(lambda: store.prior_clear(locks, baseline(), 3.0), 'producer_unknown')
                self.assertEqual([], producer.authenticated)
                restored = RestoreProducer(lambda value=value: value)
                obj, io, held, record = self.cleaned(restored)
                result = obj.finish(held, record, True, 3.0)
                self.assertFalse(result.complete); self.assertIn(PENDING, io.nodes)
                self.assertEqual([], restored.authenticated)

    def test_prior_and_restore_reject_boot_network_full_l3_changes(self):
        original_snapshot = baseline()
        addresses = list(original_snapshot.ipv4.addresses)
        addresses[0] = addresses[0]._replace(cacheinfo=(0xffffffff, 0xffffffff, 123, 457))
        values = (
            snapshot(boot='87654321-1234-1234-1234-123456789abc'),
            snapshot(station_state_sha='0' * 64),
            snapshot(station_frequency=2437),
            snapshot(ipv4=ip.IpSnapshot(tuple(addresses), original_snapshot.ipv4.routes, original_snapshot.ipv4.rules)),
            snapshot(ipv6_addresses=()), snapshot(ipv6_routes=()),
        )
        for value in values:
            with self.subTest(key=value.key()):
                producer = PriorProducer(lambda value=value: value)
                store, _, locks = self.make(prior=producer)
                self.rejection(lambda: store.prior_clear(locks, baseline(), 3.0), 'producer_unknown')
                restored = RestoreProducer(lambda value=value: value)
                obj, io, held, record = self.cleaned(restored)
                result = obj.finish(held, record, True, 3.0)
                self.assertFalse(result.complete); self.assertIn(PENDING, io.nodes)

    def test_nonlive_actor_on_either_snapshot_side_rejected_even_same_stable_key(self):
        for state in ('Z', 'X'):
            bad = snapshot()
            a = bad.stock_actors[0]
            tasks = tuple((pid, start, state if pid == a.pid else old) for pid, start, old in a.tasks)
            # Strict Snapshot ctor disallows this; corruption tests prove fresh gate is independently live-only.
            object.__setattr__(bad, 'stock_actors', (core.Actor(a.pid, a.start, a.exe, a.argv_sha, tasks),) + bad.stock_actors[1:])
            good = baseline()
            self.assertEqual(bad.key(), good.key())
            self.assertFalse(s._same_live_baseline(bad, good)); self.assertFalse(s._same_live_baseline(good, bad))
            producer = PriorProducer(lambda: bad)
            store, _, locks = self.make(prior=producer)
            self.rejection(lambda: store.prior_clear(locks, good, 3.0), 'producer_unknown')
            self.rejection(lambda: store.prior_clear(locks, bad, 3.0), 'producer_unknown')
            restored = RestoreProducer(lambda: bad)
            obj, io, held, record = self.cleaned(restored)
            self.assertFalse(obj.finish(held, record, True, 3.0).complete)
            self.assertIn(PENDING, io.nodes)

    def test_exact_snapshot_required_no_shape_or_subclass_admission(self):
        class SnapshotSubclass(core.Snapshot): pass
        source = baseline()
        value = SnapshotSubclass(*(getattr(source, key) for key in core.Snapshot.__slots__))
        for wrong in (None, True, object(), value):
            self.assertFalse(s._same_live_baseline(wrong, source))
            self.assertFalse(s._same_live_baseline(source, wrong))

    def test_authentication_boolean_and_unissued_results_still_rejected(self):
        for mode in ('bool', 'reject'):
            prior = PriorProducer(lambda: state_snapshot('S')); prior.auth_mode = mode
            store, _, locks = self.make(prior=prior)
            if mode == 'bool':
                self.rejection(lambda: store.prior_clear(locks, baseline(), 3.0), 'producer_unknown')
            else:
                with self.assertRaises(ValueError): store.prior_clear(locks, baseline(), 3.0)
            restore = RestoreProducer(lambda: state_snapshot('S')); restore.auth_mode = mode
            obj, io, held, record = self.cleaned(restore)
            self.assertFalse(obj.finish(held, record, True, 3.0).complete)
            self.assertIn(PENDING, io.nodes)

    def test_restore_reused_tuple_snapshot_or_closeproof_still_rejected(self):
        for reuse in ('tuple', 'snapshot', 'proof'):
            producer = RestoreProducer(lambda: state_snapshot('S')); producer.reuse = reuse
            store, io, locks, record = self.cleaned(producer)
            result = store.finish(locks, record, True, 3.0)
            self.assertTrue(result.terminal_durable); self.assertFalse(result.complete)
            self.assertEqual(1, len(producer.authenticated)); self.assertIn(PENDING, io.nodes)
            self.assertEqual(2, len(store._restore_observations))

    def test_missing_prior_or_restore_producer_remains_unavailable(self):
        store, _, locks = self.make()
        self.assertFalse(store.prior_clear(locks, baseline(), 3.0))
        obj, io, held, record = self.cleaned(None)
        result = obj.finish(held, record, True, 3.0)
        self.assertFalse(result.complete); self.assertFalse(result.terminal_durable)
        self.assertIn(PENDING, io.nodes)

    def test_persisted_transition_raw_task_state_change_still_rejected_zero_write(self):
        store, io, locks, record = self.prepared()
        changed = record.replace(stage='cleanup_intent', baseline=state_snapshot('S'))
        self.assertTrue(s._same_live_baseline(changed.baseline, record.baseline))
        self.assertFalse(s._same_baseline(changed.baseline, record.baseline))
        before = list(io.ops)
        self.rejection(lambda: store.commit(locks, changed), 'invalid_transition')
        self.assertEqual(before, io.ops)

    def test_persisted_current_cas_raw_task_state_change_still_rejected_not_rebased(self):
        store, io, locks, record = self.prepared()
        forged = record.replace(baseline=state_snapshot('S'))
        self.assertEqual(record.key(), forged.key()); self.assertFalse(core._same_journal(record, forged))
        before = store._canonical
        io.nodes[TARGET].data = codec.encode_journal(forged)
        self.rejection(lambda: store.current(locks), 'readback_changed')
        self.assertIs(before, store._canonical)
        self.assertTrue(store.status()['resource_pending'])

    def test_exact_source_delta_original_unchanged_and_python35_ast(self):
        raw = (BASE / 'runtime/mta_client_store.py').read_bytes()
        self.assertEqual(ORIGINAL_SHA, hashlib.sha256(raw).hexdigest())
        actual = PATH.read_text(encoding='utf-8')
        source = raw.decode('utf-8')
        helper = '\n\ndef _same_live_baseline(left, right):\n    """Fresh observations: stable identity/network plus all original actors live.\n\n    Raw task states remain in each Snapshot and in persisted journal/CAS checks.\n    This comparison is only for independently authenticated fresh producers.\n    """\n    return type(left) is core.Snapshot and type(right) is core.Snapshot and left.key() == right.key() and \\\n        all(type(actor) is core.Actor and actor.live() is True\n            for actor in left.stock_actors + right.stock_actors)\n'
        expected = source.replace('\n\n_NEXT_STAGES = {', helper + '\n\n_NEXT_STAGES = {')
        expected = expected.replace('not _same_baseline(value, baseline)', 'not _same_live_baseline(value, baseline)')
        expected = expected.replace('not _same_baseline(value[0], request.baseline)', 'not _same_live_baseline(value[0], request.baseline)')
        self.assertEqual(expected, actual)
        for path in (PATH, Path(__file__)):
            tree = ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 5))
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))


if __name__ == '__main__': unittest.main()
