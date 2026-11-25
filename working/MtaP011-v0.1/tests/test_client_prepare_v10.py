"""Six focused HOST FakeIO methods; real isolated start, not a copied algorithm."""
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
PATH = BASE / 'candidate/client-prepare-v10/runtime/mta_client_two_phase_lease.py'
ORIGINAL_SHA = '402cf2decd35aa31b47c07828e5ee14b7dd06bb5429740736fd11a54dfd11005'
BUDGET = BASE / 'candidate/client-recovery-budget-v8/runtime'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


with mock.patch.dict(sys.modules):
    marker = load('mta_client_pending', BUDGET / 'mta_client_pending.py')
    store_module = load('mta_client_store', BUDGET / 'mta_client_store.py')
    two = load('mta_client_two_phase_lease', PATH)
    # Execute the unchanged fixture source into separate globals. Only its
    # imports resolve to this isolated graph; none of its old tests are run.
    fixture = load('client_prepare_v10_fixture', BASE / 'tests/test_client_two_phase_lease.py')


class PrepareTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(sys.modules, {'mta_client_store': store_module,
            'mta_client_pending': marker, 'mta_client_two_phase_lease': two})
        patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(two.launches, 'store_module', store_module)
        patcher.start(); self.addCleanup(patcher.stop)

    def make(self, durations=(4.1,) * 6, snapshot_hook=None):
        case = fixture.TwoPhaseLeaseTests(methodName='runTest')
        case.setUp(); self.addCleanup(case.doCleanups)
        values = case.make()
        lease, provider, store, bridge, owner, kernel, reader, io = values
        self.assertIs(type(lease), two.TwoPhaseClientInitLease)
        self.assertIs(type(store), store_module.DurableClientInitStore)
        snapshots, commits, executors = [], [], []
        real_snapshot = provider.snapshot
        def timed_snapshot(deadline):
            index = len(snapshots)
            self.assertLess(index, 6)
            observed = real_snapshot(deadline)
            snapshots.append((observed, deadline, io.clock.value))  # exact refs before callback/postcheck
            io.clock.value += durations[index]
            if snapshot_hook: snapshot_hook(values, index + 1)
            return observed
        provider.snapshot = timed_snapshot

        class Prior(fixture.PriorReader):
            def read_prior(self, exact_store, locks, original, deadline):
                observed = provider.snapshot(deadline)
                if observed.key() != original.key(): raise ValueError('synthetic changed baseline')
                self.issued.append((exact_store, locks, original, observed))
                return observed
        store._prior_reader = Prior()
        real_commit = store.commit
        def committed(locks, record):
            commits.append((record, io.clock.value))
            return real_commit(locks, record)
        store.commit = committed
        real_executor = provider.executor
        def executor(deadline):
            proof = real_executor(deadline)
            executors.append((proof, deadline, io.clock.value))
            return proof
        provider.executor = executor
        return values, snapshots, commits, executors

    def test_two_preparation_reads_outside_active_twenty_all_six_and_durable_deadline_immutable(self):
        values, snapshots, commits, executors = self.make()
        lease, provider, store, bridge, owner, kernel, reader, io = values
        started = io.clock.value
        result = lease.start()
        self.assertTrue(result['client_init_ready'], result)
        self.assertEqual(6, len(snapshots)); self.assertEqual(2, len(executors))
        first, persisted_at = commits[0]
        self.assertEqual('prepared', first.stage)
        self.assertAlmostEqual(8.2, persisted_at - started)
        self.assertAlmostEqual(20, first.deadline - persisted_at)
        self.assertTrue(all(record.deadline == first.deadline for record, time in commits))
        self.assertEqual(started + 20, snapshots[0][1])
        # The isolated v8 Store gives its own fresh producer a five-second
        # slice, capped by the same preparation end; it does not reset RF TTL.
        self.assertEqual(snapshots[1][2] + 5, snapshots[1][1])
        self.assertLessEqual(snapshots[1][1], started + 20)
        self.assertEqual([first.deadline] * 4, [row[1] for row in snapshots[2:]])
        self.assertGreater(io.clock.value - started, 20)
        self.assertLess(io.clock.value, first.deadline)
        self.assertEqual(executors[0][0].actor.key(), executors[1][0].actor.key())
        self.assertEqual(2, len(owner._tickets)); self.assertEqual(2, len(lease.returned_handles))
        self.assertTrue(all(op.handle is handle for op, handle in zip(lease.launches, lease.returned_handles)))
        self.assertEqual(['register:watchdog', 'create_client', 'register:controller'], provider.calls)
        self.assertTrue(store._released is not None)  # Actual journal handoff, device retained.
        self.assertFalse(result['send_available']); self.assertFalse(result['receive_available'])

    def test_preparation_expiry_or_cancellation_never_creates_record_child_or_interface(self):
        scenarios = (((20.1, 0, 0, 0, 0, 0), False), ((4.1, 4.1, 0, 0, 0, 0), True))
        for durations, cancel in scenarios:
            requested = [False]
            def hook(values, count):
                if count == 2 and cancel: requested[0] = True
            values, snapshots, commits, _ = self.make(durations, hook)
            lease, provider, store, _, owner, _, _, io = values
            result = lease.start(cancelled=lambda: requested[0])
            self.assertFalse(result['client_init_ready']); self.assertTrue(result['cleanup_unresolved'])
            self.assertEqual([], commits); self.assertEqual([], owner._tickets)
            self.assertEqual([], provider.calls); self.assertIsNone(lease.record)
            # Existing expired preparation failure can be finish_incomplete;
            # do not rewrite it into normal restoration or a done result.
            self.assertFalse(result['cleanup_complete'])

    def test_fresh_actor_current_and_pending_changes_block_before_first_prepared(self):
        for change in ('actor', 'current', 'pending'):
            values, _, commits, executors = self.make((1, 1, 0, 0, 0, 0))
            lease, provider, store, _, owner, _, reader, io = values
            real_actors = provider.original_actors
            def change_after_read(original, deadline, change=change):
                result = real_actors(original, deadline)
                if change == 'actor':
                    actual = provider.executor_actor
                    provider.executor_actor = fixture.core.Actor(actual.pid, actual.start + 1,
                        actual.exe, actual.argv_sha, tuple((tid, start + 1, state) for tid, start, state in actual.tasks))
                elif change == 'current':
                    candidate = fixture.core.Journal(fixture.IDENTITY, 'prepared', fixture.baseline(), io.clock.value + 10)
                    io.add(fixture.RUN + '/journal.json', data=fixture.codec.encode_journal(candidate))
                else:
                    io.add(fixture.PENDING, data=b'opaque foreign pending')
                return result
            provider.original_actors = change_after_read
            result = lease.start()
            self.assertFalse(result['client_init_ready']); self.assertEqual([], commits)
            self.assertEqual([], owner._tickets); self.assertEqual([], provider.calls)
            self.assertEqual(2, len(executors))
            self.assertIsNone(lease.record)
            if change == 'actor': self.assertEqual('actor_unknown', result['reason'])

    def test_late_remaining_phase_or_cancel_after_create_does_not_refresh_or_drop_refs(self):
        for phase in ('pre_create', 'post_create', 'cancel_after_create'):
            durations = (1, 1, 20.1, 0, 0, 0) if phase == 'pre_create' else (1, 1, 1, 20.1, 0, 0)
            if phase == 'cancel_after_create': durations = (1, 1, 1, 1, 1, 1)
            requested = [False]
            def hook(values, count):
                if phase == 'cancel_after_create' and count == 4: requested[0] = True
            values, snapshots, commits, _ = self.make(durations, hook)
            lease, provider, store, bridge, owner, _, _, io = values
            result = lease.start(cancelled=lambda: requested[0])
            self.assertFalse(result['client_init_ready']); self.assertTrue(result['cleanup_unresolved'])
            self.assertFalse(result['cleanup_complete'])
            end = commits[0][0].deadline
            self.assertTrue(all(record.deadline == end for record, time in commits))
            self.assertEqual(end, lease.record.deadline)
            self.assertEqual(1, len(owner._tickets)); self.assertEqual(1, len(lease.returned_handles))
            child, op = owner._tickets[0], lease.launches[0]
            self.assertIs(child, op.child); self.assertIs(op.handle, lease.returned_handles[0])
            self.assertIs(op.handle.resource, child); self.assertTrue(child.released)
            self.assertEqual('watchdog', op.handle.ticket.role)
            if phase == 'pre_create': self.assertNotIn('create_client', provider.calls)
            else:
                self.assertIn('create_client', provider.calls)
                self.assertEqual(fixture.OWNED.key(), lease.record.owned.key())
                self.assertIs(fixture.OWNED, provider.owned)
            self.assertTrue(store._released is not None)

    def test_invalid_ttl_and_default_provider_remain_disabled_without_io(self):
        values, _, commits, _ = self.make((0,) * 6)
        lease, _, store, bridge, owner, _, _, io = values
        original = list(io.ops)
        for ttl in (True, False, 0, -1, 20.1, float('inf'), float('nan'), '20'):
            with self.assertRaises(fixture.core.ClientInitError): lease.start(ttl=ttl)
        self.assertEqual(original, io.ops); self.assertEqual([], commits); self.assertEqual([], owner._tickets)
        default = two.TwoPhaseClientInitLease(two.TwoPhaseClientInitProvider(), store,
            fixture.IDENTITY, io.clock, bridge)
        self.assertEqual('provider_unavailable', default.start()['reason'])
        self.assertEqual(original, io.ops)

    def test_original_hash_exact_start_only_delta_and_python35(self):
        before = (BASE / 'runtime/mta_client_two_phase_lease.py').read_text(encoding='utf-8')
        self.assertEqual(ORIGINAL_SHA, hashlib.sha256((BASE / 'runtime/mta_client_two_phase_lease.py').read_bytes()).hexdigest())
        after = PATH.read_text(encoding='utf-8')
        old_tree, new_tree = ast.parse(before), ast.parse(after)
        old = next(node for node in old_tree.body if isinstance(node, ast.ClassDef) and node.name == 'TwoPhaseClientInitLease')
        new = next(node for node in new_tree.body if isinstance(node, ast.ClassDef) and node.name == old.name)
        old_start = next(node for node in old.body if getattr(node, 'name', None) == 'start')
        new_start = next(node for node in new.body if getattr(node, 'name', None) == 'start')
        self.assertNotEqual(ast.dump(old_start), ast.dump(new_start))
        new.body[new.body.index(new_start)] = old_start
        self.assertEqual(ast.dump(old_tree), ast.dump(new_tree))
        expected = before.replace('        self._start_attempted = True\n',
            '        self._start_attempted = True\n        deadline = self._now() + 20  # Bounded non-RF preparation; includes lock waiting.\n')
        expected = expected.replace('                self._budget(deadline, cancelled); self._executor(deadline, starting=True)\n',
            '                self._budget(deadline, cancelled); prepared_executor = self._executor(deadline, starting=True)\n')
        extra = ("                # No external return/wait between preparation and the active\n"
            "                # record. Recheck the same F and exact empty local admission.\n"
            "                self._budget(deadline, cancelled)\n"
            "                active_executor = self._executor(deadline, starting=True)\n"
            "                if active_executor.actor.key() != prepared_executor.actor.key(): core._fail('actor_unknown')\n"
            "                self._locked()\n"
            "                if self.store.current(self.locks) is not None: core._fail('current_blocked')\n"
            "                if self.store.pending_clear(self.locks) is not True: core._fail('pending_blocked')\n"
            "                self._budget(deadline, cancelled)\n"
            "                deadline = self._now() + ttl  # Set once BEFORE the first durable Journal.\n")
        expected = expected.replace("                self._budget(deadline, cancelled); self._save(core.Journal(self.identity, 'prepared', baseline, deadline))\n",
            extra + "                self._budget(deadline, cancelled); self._save(core.Journal(self.identity, 'prepared', baseline, deadline))\n")
        self.assertEqual(expected, after)
        for path in (PATH, Path(__file__)):
            tree = ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 5))
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))


if __name__ == '__main__': unittest.main()
