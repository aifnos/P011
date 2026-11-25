"""HOST only: actual Lease/B/C/Owner methods, explicit FakeIO/FakeKernel."""
import ast
import errno
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime')))
import mta_client_two_phase_lease as two
import mta_client_process_owner as processes
import mta_client_store as stores
import mta_client_coordination as coordination
import mta_client_files as files
import mta_client_pending as pending
import mta_client_proc as proc
import mta_client_journal_codec as codec
import mta_p2p_client_init as core
from test_client_launch_registration import SidecarIo, CompositeReader
from test_client_process_owner import FakeKernel, actor, metadata, SHA
from test_client_journal_codec import baseline, IDENTITY, OWNED, STATION
from test_client_files import TOKEN, RUN, PENDING
from test_durable_client_store import PriorReader, RestoreReader
from test_p2p_client_init import caps, STATUS


class PhaseReader(CompositeReader):
    def __init__(self):
        CompositeReader.__init__(self)
        self.children, self.exited = {}, set()

    def read_actor(self, pid, expected=None):
        self.calls.append(('actor', pid, expected))
        if self.hook: self.hook('actor')
        if self.actor_result is not None: return self.actor_result
        actual = self.children.get(pid)
        if pid in self.exited: actual = None
        return proc.ProcObservation('live_actor' if actual is not None else 'absence', '', 'HOST_FAKE_ONLY',
            baseline().boot, actual, actual is None, (), True, 2, (), 12, 12, False,
            len(actual.tasks) if actual is not None else 0)

    def read_absence(self, actual, boot):
        self.calls.append(('absence', actual, boot))
        if self.hook: self.hook('absence')
        absent = actual.pid in self.exited
        return proc.ProcObservation('absence' if absent else 'unknown', '', 'HOST_FAKE_ONLY',
            boot, None, absent, (), True, 2, (), 12, 12, False, 0)


class PhaseKernel(FakeKernel):
    def __init__(self, clock, reader):
        FakeKernel.__init__(self, clock)
        self.reader = reader

    def waitpid(self, pid, flags):
        result = self.event('waitpid', pid, flags)
        return result if result is not None else ((pid, 0) if pid in self.reader.exited else (0, 0))


class Platform(two.TwoPhaseClientInitProvider):
    """Every platform observation/action here is SYNTHETIC, not a Provider."""
    def __init__(self, store, owner, reader, kernel, specs):
        self.store, self.owner, self.reader, self.kernel = store, owner, reader, kernel
        self.specs, self.owned, self.calls = dict((s.role, s) for s in specs), None, []
        self.allow_stop, self.actor_ok, self.close_ok = True, True, True
        self.close_raises = False
        self.extra_hook, self.exec_fail, self.base_changed = None, False, False
        self.executor_role, self.executor_actor = 'owner', reader.parent
        self.close_count = 0
        kernel.hook = self.event

    def event(self, name, args):
        if name == 'fork':
            child = self.owner._tickets[-1]
            self.kernel.fork_value = 200 if child.spec.role == 'watchdog' else 300
            self.reader.children[self.kernel.fork_value] = actor(self.kernel.fork_value, 20 if child.spec.role == 'watchdog' else 30)
        if name == 'write' and args[1] == b'1':
            child = next(c for c in self.owner._tickets if any(f.role == 'gate_write' and f.fd == args[0] for f in c.fds))
            if self.exec_fail: self.reader.exited.add(child.pid)
            else: self.reader.children[child.pid] = actor(child.pid, child.preexec.start, child.spec.exe, child.spec.argv_sha)
        if name == 'close':
            for child in self.owner._tickets:
                if not child.released and child.pid is not None and any(f.role == 'gate_write' and f.fd == args[0] for f in child.fds):
                    self.reader.exited.add(child.pid)
        if self.extra_hook: self.extra_hook(name, args)

    def executor(self, deadline): return core.ExecutorProof(self.executor_role, self.executor_actor, False)
    def snapshot(self, deadline):
        value = baseline()
        return core.Snapshot(value.boot, value.stock_hashes, value.stock_actors, value.station,
            'e' * 64 if self.base_changed else value.station_state_sha, value.station_frequency,
            value.interfaces if self.owned is None else value.interfaces + (self.owned,),
            value.ipv4, value.ipv6_addresses, value.ipv6_routes, value.station_completed)
    def caps(self, deadline): return caps()
    def original_actors(self, original, deadline): return self.actor_ok
    def register(self, role, identity, boot, deadline):
        self.calls.append('register:' + role)
        spec = self.specs[role]
        device = self.store._current_locks._device.fd
        stat_value = self.store._coordination._io.fstat(device)
        self.kernel.live[device] = {'meta': metadata(stat_value.st_ino, stat_value.st_mode), 'data': b'',
            'pos': 0, 'inherit': False, 'block': True, 'ofd': object()}
        return core.Ticket(('1' if role == 'watchdog' else '2') * 32, role, boot, spec.exe, spec.argv_sha)
    def register_interface(self, identity, original, deadline):
        return core.InterfaceTicket(original.boot, original.station.phy, OWNED.name, 10, 99)
    def create_client(self, ticket, deadline):
        self.calls.append('create_client'); self.owned = OWNED; return self.owned
    def origin_up(self, owned, deadline): return self.owned is not None and self.owned.key() == owned.key()
    def origin_absent(self, owned, deadline): return self.owned is None
    def delete_client(self, owned, deadline):
        self.calls.append('delete_client'); self.owned = None; return True
    def live_actor(self, handle, deadline): return self.reader.children[handle.actor.pid]
    def status(self, handle, owned, deadline): return STATUS
    def request_child_stop(self, child, deadline):
        self.calls.append('stop:' + child.spec.role)
        if not self.allow_stop: core._fail('provider_unavailable')
        self.reader.exited.add(child.pid)  # Action ONLY; Owner must actually fake-wait/reap/fresh-read.
        return None
    def close_resources(self, handles, deadline):
        self.close_count += 1
        if self.close_raises: raise OSError(errno.EIO, 'PRIVATE_CLOSE')
        return core.CloseProof(2, (True, True), (self.close_ok, self.close_ok))
    def release_exec(self, *args): raise AssertionError('old release order forbidden')
    def resolve(self, *args): raise AssertionError('target-only cleanup forbidden')
    def stop_and_reap(self, *args): raise AssertionError('old Handle-only cleanup forbidden')


class TwoPhaseLeaseTests(unittest.TestCase):
    def setUp(self):
        for cls in (coordination._LinuxIo, files._LinuxIo, pending._LinuxIo):
            for name in ('validate', 'open_root', 'open_at', 'fstat', 'stat_at', 'close',
                         'read', 'write', 'fsync', 'seek_start', 'flock', 'rename_at', 'unlink_at'):
                if hasattr(cls, name):
                    patcher = mock.patch.object(cls, name, side_effect=AssertionError('actual OS forbidden'))
                    patcher.start(); self.addCleanup(patcher.stop)
        for name in ('read_self', 'read_actor', 'read_absence'):
            patcher = mock.patch.object(proc.ProcReader, name, side_effect=AssertionError('actual proc forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        for name in ('fork', 'execve', 'kill', 'waitpid'):
            patcher = mock.patch.object(os, name, side_effect=AssertionError('actual child forbidden'), create=True)
            patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket', 'subprocess.Popen'):
            patcher = mock.patch(target, side_effect=AssertionError('actual platform forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)

    def make(self, restore=True, prior=True):
        io, reader = SidecarIo(), PhaseReader()
        store = stores.DurableClientInitStore(TOKEN, IDENTITY, _coordination_io=io, _files_io=io,
            _pending_io=io, _proc_reader=reader, _clock=io.clock,
            _restore_reader=RestoreReader() if restore else None, _prior_reader=PriorReader() if prior else None)
        self.addCleanup(store.close)
        kernel = PhaseKernel(io.clock, reader); kernel.nextfd = 1000
        owner = processes.DirectChildOwner(_os=kernel, _reader=reader, _clock=io.clock,
            _threads=lambda: 1, _flags=kernel.flags)
        specs = tuple(processes.LaunchSpec(role, '/private/' + role, ('/private/' + role, '--private'), (), SHA)
            for role in ('watchdog', 'controller'))
        bridge = two.DirectChildLaunchBridge(store, owner, specs)
        self.addCleanup(bridge.registry.close)
        provider = Platform(store, owner, reader, kernel, specs)
        lease = two.TwoPhaseClientInitLease(provider, store, IDENTITY, io.clock, bridge)
        return lease, provider, store, bridge, owner, kernel, reader, io

    def ready(self):
        values = self.make()
        result = values[0].start()
        self.assertTrue(result['client_init_ready'], result)
        return values

    def test_constructor_and_status_do_no_io(self):
        values = self.make(); before = list(values[-1].ops)
        for unused in range(2): values[0].status(); values[3].status()
        self.assertEqual(before, values[-1].ops)
        self.assertFalse(values[0].status()['send_available']); self.assertFalse(values[0].status()['rf_init_possible'])

    def test_missing_bridge_and_default_provider_unavailable_before_acquire(self):
        values = self.make(); original = list(values[-1].ops)
        empty = two.TwoPhaseClientInitLease(two.TwoPhaseClientInitProvider(), values[2], IDENTITY, values[-1].clock)
        self.assertEqual('provider_unavailable', empty.start()['reason'])
        self.assertEqual(original, values[-1].ops)
        result = two.TwoPhaseClientInitLease(two.TwoPhaseClientInitProvider(), values[2], IDENTITY,
            values[-1].clock, values[3]).start()
        self.assertFalse(result['client_init_ready']); self.assertEqual(original, values[-1].ops)

    def test_two_roles_real_components_target_saved_only_after_gate(self):
        values = self.make(); lease, provider, store, bridge, owner, kernel, reader, io = values
        events = []
        def observe(obj, operation, path, count):
            events.append((operation, path))
            if operation == 'rename' and path.startswith(RUN + '/journal.'):
                events.append(('journal-stage', codec.decode_journal(obj.nodes[path].data).stage))
        io.hook = observe
        provider.extra_hook = lambda name, args: events.append(('kernel_' + name, args))
        self.assertTrue(lease.start()['client_init_ready'])
        self.assertEqual(2, len(lease.launches)); self.assertEqual(2, len(lease.handles))
        for op in lease.launches:
            self.assertIs(op.registration.child, op.child)
            self.assertIs(op.handle.actor, op.registration.postexec)
            self.assertNotEqual(op.child.preexec.exe, op.handle.actor.exe)
        gate_positions = [i for i, item in enumerate(events) if item[0] == 'kernel_write']
        self.assertEqual(2, len(gate_positions))
        for role, gate_position in zip(('watchdog', 'controller'), gate_positions):
            self.assertLess(events.index(('journal-stage', role + '_intent')), gate_position)
            self.assertLess(gate_position, events.index(('journal-stage', role + '_saved')))
        self.assertFalse(store._finish_sealed); self.assertIn(PENDING, io.nodes)
        self.assertTrue(all(op.child.released for op in lease.launches))

    def test_full_restore_actual_owner_wait_reap_and_full_existing_finish(self):
        values = self.ready(); lease, provider, store, bridge, owner, kernel, reader, io = values
        result = lease.restore()
        self.assertTrue(result['cleanup_complete'], result)
        self.assertIs(type(lease.finish_receipt), core.FinishReceipt)
        self.assertTrue(store.authenticate_finish(lease.finish_receipt.locks, lease.finish_receipt.request_record,
            lease.finish_receipt, io.clock() + 1))
        self.assertNotIn(PENDING, io.nodes); self.assertEqual('reconciled', result['stage'])
        self.assertTrue(bridge.verify_closed()); self.assertTrue(all(c.waited and c.exit_verified for c in owner._tickets))
        self.assertEqual(['stop:controller', 'stop:watchdog'], [c for c in provider.calls if c.startswith('stop:')])

    def test_cancel_before_any_resource(self):
        values = self.make(); before = list(values[-1].ops)
        self.assertEqual('cancelled', values[0].start(cancelled=lambda: True)['reason'])
        self.assertEqual(before, values[-1].ops); self.assertEqual([], values[4]._tickets)

    def test_cancel_after_fork_preexec_without_handle_cleanup(self):
        values = self.make(); cancelled = [False]
        values[1].extra_hook = lambda name, args: cancelled.__setitem__(0, True) if name == 'fork' else None
        result = values[0].start(cancelled=lambda: cancelled[0])
        self.assertEqual('cancelled', result['reason']); self.assertEqual({}, values[0].handles)
        self.assertFalse(values[0].launches[0].child.released)
        op = values[0].launches[0]; child = op.child
        before = len(values[5].calls); at_wait = []
        launch_closed = tuple(fd.role for fd in child.fds if fd.closed)
        def observe(name, args):
            if name == 'waitpid':
                at_wait.append(tuple(fd.role for fd in child.fds if fd.closed and fd.role not in launch_closed))
                self.assertFalse(op.inventory_close_requested)
        values[1].extra_hook = observe
        self.assertTrue(values[0].restore()['cleanup_complete'])
        self.assertEqual([('gate_write',)], at_wait)
        self.assertTrue(child.waited and child.exit_verified and op.inventory_closed)
        closes = [item[1] for item in values[5].calls[before:] if item[0] == 'close']
        self.assertEqual(op.gate.fd, closes[0]); self.assertEqual(1, closes.count(op.gate.fd))
        self.assertNotIn('stop:watchdog', values[1].calls)

    def test_exec_failed_no_target_handle_is_reaped_not_unlaunched(self):
        values = self.make(); values[1].exec_fail = True
        self.assertFalse(values[0].start()['client_init_ready']); self.assertEqual({}, values[0].handles)
        op = values[0].launches[0]; self.assertTrue(op.child.fork_returned); self.assertTrue(op.child.released)
        self.assertTrue(values[0].restore()['cleanup_complete'])
        self.assertTrue(op.child.waited); self.assertTrue(op.child.exit_verified)

    def test_no_stop_producer_live_child_retains_all_owners_and_marker(self):
        values = self.ready(); values[1].allow_stop = False
        result = values[0].restore(.5)
        self.assertFalse(result['cleanup_complete']); self.assertIn(PENDING, values[-1].nodes)
        self.assertFalse(values[2]._finish_sealed); self.assertTrue(values[0].launches)
        self.assertFalse(any(c.waited for c in values[4]._tickets))

    def test_no_complete_restore_producer_never_finishes_or_clears(self):
        values = self.make(restore=False); self.assertTrue(values[0].start()['client_init_ready'])
        result = values[0].restore()
        self.assertEqual('store_unavailable', result['reason']); self.assertFalse(result['cleanup_complete'])
        self.assertIn(PENDING, values[-1].nodes); self.assertFalse(values[2]._finish_sealed)

    def test_missing_prior_producer_prevents_first_fork(self):
        values = self.make(prior=False)
        self.assertFalse(values[0].start()['client_init_ready']); self.assertEqual([], values[4]._tickets)
        self.assertFalse(any(call[0] == 'fork' for call in values[5].calls))

    def test_child_unknown_creation_retained_no_refork_no_finish(self):
        values = self.make(); values[5].faults['fork'] = KeyboardInterrupt()
        result = values[0].start(); self.assertFalse(result['client_init_ready'])
        child = values[0].launches[0].child; self.assertTrue(child.unknown); self.assertTrue(child.fds)
        self.assertTrue(result['resource_pending'])
        self.assertFalse(values[0].restore()['cleanup_complete']); self.assertFalse(values[2]._finish_sealed)
        before = len(values[5].calls); values[0].start(); self.assertEqual(before, len(values[5].calls))

    def test_prepare_partial_registration_retained(self):
        values = self.make(); original = values[4].register
        def partial(*args): original(*args); raise MemoryError()
        values[4].register = partial
        self.assertFalse(values[0].start()['client_init_ready'])
        self.assertTrue(values[0].launches[0].prepare_unknown); self.assertEqual(1, len(values[4]._tickets))
        self.assertIsNone(values[0].launches[0].child)
        self.assertFalse(values[0].restore()['cleanup_complete'])

    def test_malformed_launch_result_retained_no_false_completion(self):
        values = self.make(); original = values[4].launch; foreign = object()
        def malformed(child): original(child); return foreign
        values[4].launch = malformed
        self.assertFalse(values[0].start()['client_init_ready'])
        self.assertIs(values[0].launches[0].returned, foreign)
        self.assertFalse(values[0].restore()['cleanup_complete'])

    def test_persist_failure_never_gate_and_c_pending_not_washed(self):
        values = self.make(); values[-1].faults[('fsync', RUN + '/launch-watchdog.00000001.tmp')] = OSError(errno.EIO, 'PRIVATE')
        self.assertFalse(values[0].start()['client_init_ready'])
        self.assertEqual([], values[5].writes); self.assertTrue(values[3].registry._pending)
        self.assertFalse(values[0].restore()['cleanup_complete']); self.assertIn(PENDING, values[-1].nodes)

    def test_cancel_during_release_keeps_late_actual_child(self):
        values = self.make(); cancelled = [False]
        # Actual gate write signals an in-flight late cancellation. It is not
        # retroactively treated as never-exec or a hard-preempted callback.
        values[1].extra_hook = lambda name, args: cancelled.__setitem__(0, True) if name == 'write' else None
        result = values[0].start(cancelled=lambda: cancelled[0])
        self.assertEqual('cancelled', result['reason']); self.assertTrue(values[0].launches[0].child.released)
        self.assertEqual({}, values[0].handles); self.assertTrue(values[0].restore()['cleanup_complete'])

    def test_late_postexec_handle_retained_saved_before_cancel(self):
        values = self.make(); cancelled = [False]
        def after_post(io, operation, path, count):
            if operation == 'fsync' and path == RUN and values[3]._operations and \
                    values[3]._operations[0].registration.candidate_data and b'post_exec_durable' in values[3]._operations[0].registration.candidate_data:
                cancelled[0] = True
        values[-1].hook = after_post
        result = values[0].start(cancelled=lambda: cancelled[0])
        self.assertEqual('cancelled', result['reason']); self.assertIn('watchdog', values[0].handles)
        self.assertEqual('watchdog_saved', values[0].record.stage)
        self.assertTrue(values[0].restore()['cleanup_complete'])

    def test_unknown_stop_action_keeps_exact_child_no_retry(self):
        values = self.ready()
        def unknown(child, deadline): raise MemoryError()
        values[1].request_child_stop = unknown
        self.assertFalse(values[0].restore()['cleanup_complete'])
        self.assertTrue(all(op.stop_unknown for op in values[0].launches))
        values[1].request_child_stop = lambda *args: self.fail('unknown action must not repeat')
        self.assertFalse(values[0].restore()['cleanup_complete'])

    def test_provider_close_unknown_not_erased_by_later_flags(self):
        values = self.ready(); values[1].close_raises = True
        result = values[0].restore()
        self.assertFalse(result['cleanup_complete']); self.assertTrue(result['resource_pending'])
        self.assertTrue(values[0]._provider_close_unknown); self.assertEqual(1, values[1].close_count)
        values[1].close_raises = False
        self.assertFalse(values[0].restore()['cleanup_complete']); self.assertEqual(1, values[1].close_count)
        self.assertIn(PENDING, values[-1].nodes)

    def test_self_child_executor_rejected_before_cleanup(self):
        values = self.ready(); values[1].executor_actor = values[0].launches[0].child.preexec
        before = list(values[5].calls)
        self.assertEqual('self_actor_recovery', values[0].restore()['reason'])
        self.assertEqual(before, values[5].calls)

    def test_external_executor_not_orphan_reap_permission(self):
        values = self.ready(); values[1].executor_role = 'external_finalizer'
        self.assertFalse(values[0].restore()['cleanup_complete'])
        self.assertFalse(any(c.waited for c in values[4]._tickets))

    def test_baseline_change_blocks_network_delete_and_finish(self):
        values = self.ready(); values[1].base_changed = True
        self.assertEqual('baseline_changed', values[0].restore()['reason'])
        self.assertNotIn('delete_client', values[1].calls); self.assertFalse(values[2]._finish_sealed)

    def test_unregistered_owner_ticket_blocks_complete_inventory(self):
        values = self.ready()
        # An actual original registry not represented in the two phase inventory
        # cannot be hidden merely because handles.values() has two entries.
        values[4]._tickets.append(processes.ChildTicket(values[4], values[4]._tickets[0].spec, 3, 10))
        self.assertFalse(values[0].restore()['cleanup_complete']); self.assertFalse(values[3].verify_closed())

    def test_passive_status_never_closes_reads_or_callbacks(self):
        values = self.ready(); before_io = list(values[-1].ops); before_kernel = list(values[5].calls)
        values[1].snapshot = lambda *args: self.fail('status callback')
        values[0].status(); values[3].status()
        self.assertEqual(before_io, values[-1].ops); self.assertEqual(before_kernel, values[5].calls)

    def test_strict_budgets_and_fixed_private_status(self):
        values = self.make()
        for wrong in (True, 0, float('nan'), float('inf'), 10**1000):
            with self.assertRaises(core.ClientInitError): values[0].start(wrong)
        status = repr(values[0].status())
        for secret in (TOKEN, RUN, baseline().boot, '/private/', 'pid', 'argv_sha'): self.assertNotIn(secret, status)

    def test_python35_ast_and_no_direct_os_or_protocol_fallback(self):
        with open(two.__file__, encoding='utf-8') as source: tree = ast.parse(source.read(), feature_version=(3, 5))
        with open(__file__, encoding='utf-8') as source: ast.parse(source.read(), feature_version=(3, 5))
        names = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        self.assertFalse({'fork', 'execve', 'kill', 'waitpid', 'release_exec', 'stop_and_reap'} & names)
        self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))

    def test_known_negative_fork_closes_original_inventory_without_fake_actor(self):
        values = self.make(); values[5].faults['fork'] = OSError(errno.EAGAIN, 'HOST negative fork')
        self.assertFalse(values[0].start()['client_init_ready'])
        child = values[0].launches[0].child
        self.assertTrue(child.fork_negative); self.assertIsNone(child.preexec)
        self.assertTrue(values[0].restore()['cleanup_complete'])
        self.assertFalse(child.waited); self.assertEqual({}, values[0].handles)

    def test_expiry_before_persist_cannot_release_gate_or_erase_refs(self):
        values = self.make()
        def expire(name, args):
            if name == 'fork': values[-1].clock.value = 21.0
        values[1].extra_hook = expire
        result = values[0].start(ttl=20)
        self.assertFalse(result['client_init_ready']); self.assertEqual([], values[5].writes)
        self.assertTrue(values[0].launches); self.assertIsNotNone(values[0].launches[0].child)
        self.assertFalse(values[0].launches[0].child.released)

    def test_existing_full_finish_rejects_non_snapshot_restore_producer(self):
        values = self.ready(); values[2]._restore_reader.mode = 'bool'
        result = values[0].restore()
        self.assertFalse(result['cleanup_complete']); self.assertTrue(values[2]._finish_sealed)
        self.assertIn(PENDING, values[-1].nodes)
        self.assertIs(type(values[0].finish_receipt), core.FinishReceipt)
        self.assertFalse(values[0].finish_receipt.complete)

    def test_original_owner_close_unknown_is_visible_and_not_reclosed(self):
        values = self.ready(); values[5].faults['close'] = OSError(errno.EIO, 'HOST close unknown')
        result = values[0].restore()
        self.assertFalse(result['cleanup_complete']); self.assertTrue(result['resource_pending'])
        attempted = sum(f.attempted for child in values[4]._tickets for f in child.fds)
        closed_calls = len(values[5].closed)
        values[5].faults.clear(); values[0].restore()
        self.assertEqual(attempted, sum(f.attempted for child in values[4]._tickets for f in child.fds))
        self.assertEqual(closed_calls, len(values[5].closed)); self.assertIn(PENDING, values[-1].nodes)

    def test_known_pregate_wait_timeout_reobserves_original_gate_without_reclose(self):
        values = self.make(); cancelled = [False]
        values[1].extra_hook = lambda name, args: cancelled.__setitem__(0, True) if name == 'fork' else None
        self.assertEqual('cancelled', values[0].start(cancelled=lambda: cancelled[0])['reason'])
        op = values[0].launches[0]; child = op.child
        launch_closed = tuple(fd.role for fd in child.fds if fd.closed)
        def delay_exit(name, args):
            if name == 'close' and args[0] == next(fd.fd for fd in child.fds if fd.role == 'gate_write'):
                values[6].exited.discard(child.pid)
        values[1].extra_hook = delay_exit
        first = values[0].restore()
        self.assertFalse(first['cleanup_complete']); self.assertTrue(op.gate_closed)
        self.assertFalse(child.waited or child.unknown or op.inventory_close_requested)
        self.assertEqual(['gate_write'], [fd.role for fd in child.fds if fd.closed and fd.role not in launch_closed])
        count = len([event for event in values[5].calls if event[0] == 'close' and event[1] == op.gate.fd])
        values[6].exited.add(child.pid); values[1].extra_hook = None
        self.assertTrue(values[0].restore()['cleanup_complete'])
        self.assertTrue(child.waited and child.exit_verified)
        self.assertEqual(count, len([event for event in values[5].calls if event[0] == 'close' and event[1] == op.gate.fd]))

    def test_acquire_unknown_original_inventory_remains_passive_pending(self):
        values = self.make()
        values[-1].faults[('open', '/')] = MemoryError()
        result = values[0].start()
        self.assertFalse(result['client_init_ready']); self.assertTrue(result['resource_pending'])
        self.assertIsNone(values[0].locks); self.assertTrue(values[2]._coordination._inventory)
        self.assertTrue(values[2].status()['resource_pending']); self.assertEqual([], values[4]._tickets)
        before = list(values[-1].ops); values[0].status()
        self.assertEqual(before, values[-1].ops)


if __name__ == '__main__': unittest.main()
