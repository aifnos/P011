"""HOST only: actual component code over explicit FakeIO/FakeKernel.

No OS files, locks, fork, exec, process scan, sockets or device operations.
"""
import ast
import errno
import os
import stat
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime')))
import mta_client_launch_registration as launch
import mta_client_store as stores
import mta_client_process_owner as processes
import mta_client_coordination as coordination
import mta_client_files as files
import mta_client_pending as pending
import mta_client_proc as proc
import mta_p2p_client_init as core
import p011_json as json
from test_client_files import TOKEN, RUN, PENDING
from test_client_journal_codec import baseline, IDENTITY, OWNED
from test_durable_client_store import StoreIo
from test_client_process_owner import FakeReader, FakeKernel, actor, metadata, SHA


class CompositeReader(FakeReader):
    def read_self(self):
        self.calls.append(('self',))
        if self.hook: self.hook('self')
        return self.self_result or proc.ProcObservation('live_actor', '', 'HOST_FAKE_ONLY',
            baseline().boot, self.parent, False, (), True, 2, (), 12, 12, False, len(self.parent.tasks))


class SidecarIo(StoreIo):
    def __init__(self):
        self.unique_inode = 1000
        StoreIo.__init__(self)

    def add(self, *args, **kwargs):
        node = StoreIo.add(self, *args, **kwargs)
        self.unique_inode += 1
        node.ino = self.unique_inode
        return node


class LaunchRegistrationTests(unittest.TestCase):
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
        for target in ('ctypes.CDLL', 'socket.socket'):
            patcher = mock.patch(target, side_effect=AssertionError('actual native/network forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)

    def make(self):
        io, reader = SidecarIo(), CompositeReader()
        store = stores.DurableClientInitStore(TOKEN, IDENTITY,
            _coordination_io=io, _files_io=io, _pending_io=io, _proc_reader=reader,
            _clock=io.clock)
        self.addCleanup(store.close)
        locks = store.acquire(IDENTITY, 3.0)
        journal = store.commit(locks, core.Journal(IDENTITY, 'prepared', baseline(), 10.0))
        kernel = FakeKernel(io.clock)
        # Both explicit HOST adapters model the same retained device FD/OFD.
        # This seam is synthetic, not a kernel inheritance claim.
        device = locks._device.fd
        actual = io.fstat(device)
        kernel.live[device] = {'meta': metadata(actual.st_ino, actual.st_mode),
            'data': b'', 'pos': 0, 'inherit': False, 'block': True, 'ofd': object()}
        kernel.nextfd = 1000
        threads = [1]
        owner = processes.DirectChildOwner(_os=kernel, _reader=reader, _clock=io.clock,
            _threads=lambda: threads[0], _flags=kernel.flags)
        registry = launch.DurableLaunchRegistry(store, owner)
        self.addCleanup(registry.close)
        return registry, store, io, owner, reader, kernel, locks, journal, threads

    def registered(self, role='watchdog'):
        values = self.make()
        registry, store, io, owner, reader, kernel, locks, journal, threads = values
        if role == 'controller':
            wt = core.Ticket('e' * 32, 'watchdog', journal.baseline.boot, '/private/watchdog', 'c' * 64)
            wa = core.Actor(301, 20, wt.exe, wt.argv_sha, ((301, 20, 'S'),))
            journal = store.commit(locks, journal.replace(stage='watchdog_intent', watchdog_ticket=wt))
            journal = store.commit(locks, journal.replace(stage='watchdog_saved', watchdog=wa))
            it = core.InterfaceTicket(journal.baseline.boot, 0, OWNED.name, 0xffffffff, 0xffffffff)
            journal = store.commit(locks, journal.replace(stage='interface_intent', interface_ticket=it))
            journal = store.commit(locks, journal.replace(stage='interface_owned', owned=OWNED))
        spec = processes.LaunchSpec(role, '/private/' + role, ('/private/' + role, '--private'), (), SHA)
        target = core.Ticket('a' * 32, role, journal.baseline.boot, spec.exe, spec.argv_sha)
        journal = store.commit(locks, journal.replace(stage=role + '_intent', **{role + '_ticket': target}))
        child = owner.register(spec, locks._device.fd, journal.deadline)
        record = registry.register(target, child)
        return values + (spec, target, child, record)

    def released(self, role='watchdog'):
        values = self.registered(role)
        registry, owner, child, record = values[0], values[3], values[-2], values[-1]
        owner.launch(child)
        receipt = registry.release(record)
        self.assertIs(receipt, record.persist_receipt)
        return values

    def final_actor(self, values):
        spec, child = values[-4], values[-2]
        result = actor(child.pid, child.preexec.start, spec.exe, spec.argv_sha)
        values[4].child = result
        return result

    def reject(self, function, code=None):
        with self.assertRaises(launch.LaunchRegistrationError) as caught: function()
        if code is not None: self.assertEqual(code, caught.exception.code)
        self.assertIn(caught.exception.code, launch._CODES)
        for text in (TOKEN, RUN, '/private/', 'pid', 'HOST'):
            self.assertNotIn(text, str(caught.exception))

    def target_path(self, values):
        return RUN + '/' + launch.NAMES[values[-3].role]

    def assert_no_gate(self, values):
        self.assertEqual([], values[5].writes)
        self.assertFalse(values[-2].released)

    def test_constructor_registration_and_status_pure(self):
        values = self.make()
        registry, store, io, owner = values[:4]
        before = len(io.ops)
        unused = launch.DurableLaunchRegistry(store, owner)
        self.assertEqual(before, len(io.ops))
        status = unused.status()
        self.assertFalse(status['complete']); self.assertFalse(status['provider_ready'])
        self.assertFalse(status['rf_admission']); self.assertFalse(status['manifest_authenticated'])
        self.assertEqual(0, status['registration_count'])

    def test_constructor_strict_config_without_path_or_recovery_api(self):
        values = self.make()
        for wrong in (True, 0, float('nan'), float('inf'), 10**1000):
            self.reject(lambda: launch.DurableLaunchRegistry(values[1], values[3], wrong), 'invalid_config')
        self.reject(lambda: launch.DurableLaunchRegistry(object(), values[3]), 'invalid_config')
        self.reject(lambda: launch.DurableLaunchRegistry(values[1], object()), 'invalid_config')
        for method in ('recover', 'finish', 'clear', 'unlink', 'start', 'launch'):
            self.assertFalse(hasattr(values[0], method))

    def test_exact_registration_once_before_launch_no_io(self):
        values = self.registered(); registry, io = values[0], values[2]
        child, record = values[-2:]
        self.assertFalse(child.started); self.assertEqual('registered', record.phase)
        before = len(io.ops)
        self.reject(lambda: registry.register(values[-3], child), 'already_attempted')
        fake = launch.LaunchRegistration(registry._issuer, record.target, child, record.locks)
        self.reject(lambda: registry.release(fake), 'not_registered')
        self.assertEqual(before, len(io.ops))

    def test_target_spec_device_or_owner_mismatch_rejected(self):
        values = self.registered(); registry, owner, child = values[0], values[3], values[-2]
        wrong = core.Ticket('b' * 32, 'watchdog', baseline().boot, '/private/other', 'b' * 64)
        self.reject(lambda: registry.register(wrong, child), 'invalid_ticket')
        child.original_device_fd += 1
        self.reject(lambda: registry.register(values[-3], child), 'invalid_ticket')
        self.assertFalse(owner._os.writes)

    def test_real_preexec_persist_fsync_readback_before_gate(self):
        values = self.registered(); registry, io, owner, kernel = values[0], values[2], values[3], values[5]
        child, record = values[-2:]
        events = []
        io.hook = lambda obj, operation, path, count: events.append((operation, path))
        kernel.hook = lambda operation, args: events.append(('kernel_' + operation, args))
        owner.launch(child)
        receipt = registry.release(record)
        self.assertIs(child.persist_receipt, receipt); self.assertIs(receipt.actor, child.preexec)
        self.assertEqual('exec_gate_released', record.phase); self.assertTrue(child.released)
        document = json.loads(io.nodes[self.target_path(values)].data.decode('ascii'))
        self.assertEqual('pre_exec_durable', document['stage'])
        self.assertEqual(child.preexec.exe, document['preexec']['exe'])
        self.assertNotEqual(values[-4].exe, document['preexec']['exe'])
        self.assertIsNone(document['postexec'])
        gate = next(i for i, event in enumerate(events) if event[0] == 'kernel_write')
        directory_sync = max(i for i, event in enumerate(events) if event == ('fsync', RUN))
        file_read = max(i for i, event in enumerate(events) if event == ('read', self.target_path(values)))
        self.assertLess(directory_sync, gate); self.assertLess(file_read, gate)
        self.assertTrue(all(t.closed for t in registry._inventory))
        self.assertEqual(1, len(kernel.writes))

    def test_python_preexec_cannot_be_target_handle(self):
        values = self.registered(); values[3].launch(values[-2])
        with self.assertRaises(core.ClientInitError):
            core.Handle(values[-3], values[-2].preexec, values[-2])
        self.assertIsNone(values[-1].handle)

    def test_postexec_actual_identity_durable_then_handle(self):
        values = self.released(); registry, record = values[0], values[-1]
        actual = self.final_actor(values)
        handle = registry.resolve(record)
        self.assertIs(type(handle), core.Handle); self.assertIs(handle.actor, actual)
        self.assertIs(handle.resource, values[-2]); self.assertIs(record.handle, handle)
        self.assertEqual('post_exec_durable', record.phase)
        document = json.loads(values[2].nodes[self.target_path(values)].data.decode('ascii'))
        self.assertEqual(actual.exe, document['postexec']['exe'])
        self.assertNotEqual(document['preexec']['exe'], document['postexec']['exe'])
        self.assertFalse(registry.status()['complete']); self.assertFalse(registry.status()['child_exit_verified'])
        self.reject(lambda: registry.resolve(record), 'invalid_phase')

    def test_controller_fixed_second_role_no_arbitrary_filename(self):
        values = self.released('controller'); actual = self.final_actor(values)
        handle = values[0].resolve(values[-1])
        self.assertIs(handle.actor, actual)
        self.assertIn(RUN + '/launch-controller.json', values[2].nodes)
        self.assertNotIn(RUN + '/launch-watchdog.json', values[2].nodes)
        self.assertLess(len(values[1]._files._inventory), files.MAX_RESOURCES)

    def test_preexec_waiting_none_is_not_identity_or_exit_proof(self):
        values = self.released(); before = bytes(values[2].nodes[self.target_path(values)].data)
        self.assertIsNone(values[0].resolve(values[-1]))
        self.assertIsNone(values[-1].handle)
        self.assertEqual(before, values[2].nodes[self.target_path(values)].data)
        self.assertEqual('exec_gate_released', values[-1].phase)
        self.assertFalse(values[0].status()['child_exit_verified'])

    def test_postexec_pid_start_boot_or_unexpected_exe_never_handle(self):
        for field in ('start', 'boot', 'exe'):
            values = self.released(); registry, reader, child = values[0], values[4], values[-2]
            self.final_actor(values)
            if field == 'start': reader.child = actor(child.pid, child.preexec.start + 1, values[-4].exe, values[-4].argv_sha)
            elif field == 'boot': reader.actor_result = proc.ProcObservation('live_actor', '', 'HOST', '22222222-2222-2222-2222-222222222222',
                reader.child, False, (), True, 2, (), 0, 0, False, 1)
            else: reader.child = actor(child.pid, child.preexec.start, '/private/unknown', values[-4].argv_sha)
            if field == 'exe': self.reject(lambda: registry.resolve(values[-1]), 'actor_unknown')
            else: self.assertIsNone(registry.resolve(values[-1]))
            self.assertIsNone(values[-1].handle)
            self.assertEqual(0, registry.status()['postexec_durable_count'])

    def test_postexec_multitask_or_zombie_not_valid_single_actor(self):
        for state in ('Z', 'multi'):
            values = self.released(); child, spec = values[-2], values[-4]
            tasks = ((child.pid, child.preexec.start, 'Z'),) if state == 'Z' else (
                (child.pid, child.preexec.start, 'S'), (child.pid + 1, child.preexec.start + 1, 'S'))
            values[4].child = actor(child.pid, child.preexec.start, spec.exe, spec.argv_sha, tasks)
            if state == 'multi': self.reject(lambda: values[0].resolve(values[-1]), 'actor_unknown')
            else: self.assertIsNone(values[0].resolve(values[-1]))
            self.assertIsNone(values[-1].handle)

    def test_foreign_existing_sidecar_same_schema_never_adopted(self):
        values = self.registered(); values[3].launch(values[-2])
        original = values[2].add(self.target_path(values), data=b'{"version":1}')
        self.reject(lambda: values[0].release(values[-1]), 'component_error')
        self.assertIs(original, values[2].nodes[self.target_path(values)])
        self.assert_no_gate(values)

    def test_preexec_file_fsync_failure_no_gate_and_exact_refs_retained(self):
        values = self.registered(); values[3].launch(values[-2])
        path = RUN + '/launch-watchdog.00000001.tmp'
        values[2].faults[('fsync', path)] = OSError(errno.EIO, 'private')
        self.reject(lambda: values[0].release(values[-1]), 'component_error')
        self.assert_no_gate(values); self.assertTrue(values[-1].unknown)
        self.assertTrue(values[0]._inventory)
        self.assertIsNotNone(values[-1].candidate_data)
        self.assertIsNone(values[-1].persist_receipt)

    def test_rename_consumed_exception_keeps_unknown_not_retried(self):
        values = self.registered(); values[3].launch(values[-2])
        original = values[2].rename_at
        def consumed(parent, source, target):
            original(parent, source, target)
            raise OSError(errno.EIO, 'private unknown result')
        values[2].rename_at = consumed
        self.reject(lambda: values[0].release(values[-1]), 'component_error')
        self.assertIn(self.target_path(values), values[2].nodes)
        self.assertTrue(values[-1].published_unknown)
        before = len(values[2].ops)
        self.reject(lambda: values[0].release(values[-1]), 'resource_pending')
        self.assertEqual(before, len(values[2].ops)); self.assert_no_gate(values)

    def test_postrename_fsync_unknown_retains_publication_and_no_gate(self):
        values = self.registered(); values[3].launch(values[-2])
        # Only the sidecar directory fsync, not earlier prepared writes.
        values[2].faults[('fsync', RUN)] = OSError(errno.EIO, 'private')
        self.reject(lambda: values[0].release(values[-1]), 'component_error')
        self.assertEqual(values[-1].data, values[2].nodes[self.target_path(values)].data)
        self.assertTrue(values[-1].published_unknown); self.assert_no_gate(values)

    def test_same_bytes_new_inode_after_publish_never_receipt(self):
        values = self.registered(); values[3].launch(values[-2])
        def substitute(io, operation, path, count):
            if operation == 'fsync' and path == RUN:
                data = io.nodes[self.target_path(values)].data
                io.add(self.target_path(values), data=data)
        values[2].hook = substitute
        self.reject(lambda: values[0].release(values[-1]), 'component_error')
        self.assertIsNone(values[-1].persist_receipt); self.assert_no_gate(values)

    def test_unknown_open_retains_original_creation_ticket(self):
        values = self.registered(); values[3].launch(values[-2])
        original = values[2].open_at
        def hidden(parent, name, flags, mode=0):
            fd = original(parent, name, flags, mode)
            if name.startswith('launch-'): raise RuntimeError('private hidden fd')
            return fd
        values[2].open_at = hidden
        self.reject(lambda: values[0].release(values[-1]), 'component_error')
        ticket = values[0]._inventory[0]
        self.assertIsNone(ticket.fd); self.assertTrue(ticket.opening_unknown)
        self.assertIs(ticket.io, values[2]); self.assertIs(ticket.creator, hidden)
        self.assertFalse(ticket.attempted); self.assert_no_gate(values)
        values[0].close(); self.assertTrue(values[0].status()['resource_pending'])

    def test_bool_fd_and_alias_result_never_blind_close(self):
        for malformed in (True, 'fd', 'alias'):
            values = self.registered(); values[3].launch(values[-2])
            original = values[2].open_at
            def bad(parent, name, flags, mode=0):
                if name.startswith('launch-'):
                    return values[6]._device.fd if malformed == 'alias' else malformed
                return original(parent, name, flags, mode)
            values[2].open_at = bad
            self.reject(lambda: values[0].release(values[-1]), 'component_error')
            values[0].close()
            self.assertFalse(values[0]._inventory[0].attempted)
            self.assertIn(values[6]._device.fd, values[2].handles)
            self.assert_no_gate(values)

    def test_live_child_fd_alias_retained_not_closed_as_sidecar(self):
        values = self.registered(); values[3].launch(values[-2])
        child_fd = next(t for t in values[-2].fds if t.closed is not True)
        original = values[2].open_at
        values[2].open_at = lambda parent, name, flags, mode=0: child_fd.fd if name.startswith('launch-') else original(parent, name, flags, mode)
        self.reject(lambda: values[0].release(values[-1]), 'component_error')
        values[0].close()
        self.assertEqual(child_fd.fd, values[0]._inventory[0].fd)
        self.assertFalse(values[0]._inventory[0].attempted)
        self.assertIn(child_fd.fd, values[5].live)
        self.assert_no_gate(values)

    def test_write_bool_or_zero_not_valid_byte_count(self):
        for wrong in (True, 0, b'1'):
            values = self.registered(); values[3].launch(values[-2])
            values[2].write_result = wrong
            self.reject(lambda: values[0].release(values[-1]), 'component_error')
            self.assertIsNone(values[-1].persist_receipt); self.assert_no_gate(values)

    def test_unknown_close_independent_once_and_sticky(self):
        values = self.registered(); values[3].launch(values[-2])
        original = values[2].open_at
        def mark(parent, name, flags, mode=0):
            fd = original(parent, name, flags, mode)
            if name.startswith('launch-'): values[2].keep_open.add(fd)
            return fd
        values[2].open_at = mark
        self.reject(lambda: values[0].release(values[-1]), 'component_error')
        ticket = values[0]._inventory[0]
        self.assertTrue(ticket.attempted); self.assertFalse(ticket.closed)
        values[2].keep_open.clear()
        values[0].close(); values[0].close()
        self.assertEqual(1, values[2].closed.count(ticket.fd))
        self.assertTrue(values[0].status()['resource_pending']); self.assert_no_gate(values)

    def test_parent_single_thread_and_own_marker_freshness_no_gate(self):
        for field in ('threads', 'parent', 'marker'):
            values = self.registered(); values[3].launch(values[-2])
            if field == 'threads': values[8][0] = 2
            elif field == 'parent': values[4].parent = actor(start=11)
            else: values[2].nodes[PENDING].data += b'x'
            self.reject(lambda: values[0].release(values[-1]), 'component_error')
            self.assert_no_gate(values)

    def test_store_lock_epoch_intent_or_target_boot_change_no_gate(self):
        for field in ('epoch', 'intent', 'boot'):
            values = self.registered(); values[3].launch(values[-2])
            if field == 'epoch': values[1]._epoch = object()
            elif field == 'intent': values[1].commit(values[6], values[1].current(values[6]).replace(stage='cleanup_intent'))
            else: values[-1].target = core.Ticket('a' * 32, 'watchdog', '22222222-2222-2222-2222-222222222222', values[-4].exe, values[-4].argv_sha)
            self.reject(lambda: values[0].release(values[-1]), 'component_error')
            self.assert_no_gate(values)

    def test_original_components_anchor_and_fd_ticket_not_replaceable(self):
        for field in ('_files', '_coordination', '_marker', '_binding', 'anchor', 'run_ticket', 'device_fd'):
            values = self.registered(); values[3].launch(values[-2])
            store, record = values[1], values[-1]
            saved = getattr(store, field) if field.startswith('_') else None
            anchor = store._files._anchors[-1]
            device_fd = record.locks._device.fd
            try:
                if field.startswith('_'): setattr(store, field, object())
                elif field == 'anchor': store._files._anchors[-1] = tuple(list(anchor))
                elif field == 'run_ticket':
                    other = files._Fd(values[2], 'foreign_same_numeric_fd')
                    other.fd = anchor[0].fd
                    store._files._anchors[-1] = (other,) + anchor[1:]
                else: record.locks._device.fd = device_fd + 1
                self.reject(lambda: values[0].release(record), 'component_error')
                self.assert_no_gate(values)
                self.assertEqual(0, len(values[0]._inventory))
                self.assertIs(record._borrowed[5], anchor[0])
                self.assertIs(record._borrowed[7], record.locks._device)
            finally:
                if field.startswith('_'): setattr(store, field, saved)
                else: store._files._anchors[-1] = anchor
                record.locks._device.fd = device_fd

    def test_expiry_before_callback_or_after_durable_never_gate(self):
        for timing in ('before', 'after'):
            values = self.registered(); values[3].launch(values[-2])
            if timing == 'before': values[2].clock.value = 10.0
            else:
                def expire(io, operation, path, count):
                    if operation == 'fsync' and path == RUN: io.clock.value = 10.0
                values[2].hook = expire
            self.reject(lambda: values[0].release(values[-1]), 'component_error')
            self.assert_no_gate(values)
            if timing == 'after': self.assertIsNotNone(values[-1].data)

    def test_postexec_io_failure_never_returns_handle_preserves_actual_actor(self):
        values = self.released(); actual = self.final_actor(values)
        path = RUN + '/launch-watchdog.00000002.tmp'
        values[2].faults[('fsync', path)] = OSError(errno.EIO, 'private')
        self.reject(lambda: values[0].resolve(values[-1]), 'component_error')
        self.assertIs(values[-1].postexec, actual); self.assertIsNone(values[-1].handle)
        self.assertTrue(values[-2].released); self.assertTrue(values[-1].unknown)
        self.assertEqual('pre_exec_durable', json.loads(values[2].nodes[self.target_path(values)].data.decode('ascii'))['stage'])

    def test_postexec_persistence_after_rf_deadline_does_not_extend_authorization(self):
        values = self.released(); actual = self.final_actor(values)
        values[2].clock.value = 11.0
        handle = values[0].resolve(values[-1])
        self.assertIs(handle.actor, actual)
        self.assertEqual(10.0, values[-2].deadline)
        self.assertEqual(10.0, values[1].current(values[6]).deadline)
        self.assertFalse(values[0].status()['rf_admission'])

    def test_two_actual_role_sidecars_over_full_store_stages_keep_inventory_bounded(self):
        values = self.released(); watchdog = self.final_actor(values)
        values[0].resolve(values[-1])
        registry, store, io, owner, reader, kernel, locks = values[:7]
        journal = store.current(locks)
        journal = store.commit(locks, journal.replace(stage='watchdog_saved', watchdog=watchdog))
        it = core.InterfaceTicket(journal.baseline.boot, 0, OWNED.name, 0xffffffff, 0xffffffff)
        journal = store.commit(locks, journal.replace(stage='interface_intent', interface_ticket=it))
        journal = store.commit(locks, journal.replace(stage='interface_owned', owned=OWNED))
        spec = processes.LaunchSpec('controller', '/private/controller', ('/private/controller', '--private'), (), SHA)
        target = core.Ticket('b' * 32, 'controller', journal.baseline.boot, spec.exe, spec.argv_sha)
        journal = store.commit(locks, journal.replace(stage='controller_intent', controller_ticket=target))
        child = owner.register(spec, locks._device.fd, journal.deadline)
        record = registry.register(target, child)
        reader.child = actor(300, 30); kernel.fork_value = 300
        owner.launch(child); registry.release(record)
        reader.child = actor(300, 30, spec.exe, spec.argv_sha)
        handle = registry.resolve(record)
        journal = store.commit(locks, journal.replace(stage='controller_saved', controller=handle.actor))
        self.assertEqual('controller_saved', store.current(locks).stage)
        self.assertEqual(2, registry.status()['preexec_durable_count'])
        self.assertEqual(2, registry.status()['postexec_durable_count'])
        self.assertLess(len(registry._inventory), launch.MAX_FDS)
        self.assertLess(len(store._files._inventory), files.MAX_RESOURCES)
        self.assertIn(RUN + '/launch-watchdog.json', io.nodes)
        self.assertIn(RUN + '/launch-controller.json', io.nodes)
        self.assertTrue(all(t.closed for t in registry._inventory))

    def test_sidecar_foreign_generation_after_release_no_handle(self):
        values = self.released(); self.final_actor(values)
        node = values[2].nodes[self.target_path(values)]
        values[2].add(self.target_path(values), data=node.data)
        self.reject(lambda: values[0].resolve(values[-1]), 'foreign_file')
        self.assertIsNone(values[-1].handle); self.assertTrue(values[-2].released)

    def test_postpublish_fresh_actor_absence_reexec_or_unknown_no_handle(self):
        for fault in ('exit', 'reexec', 'unknown'):
            values = self.released(); actual = self.final_actor(values)
            def later(io, operation, path, count):
                if operation != 'fsync' or path != RUN: return
                if fault == 'exit':
                    values[4].actor_result = proc.ProcObservation('absence', '', 'HOST', baseline().boot,
                        None, True, (), True, 2, (), 0, 0, False, 0)
                elif fault == 'reexec': values[4].child = actor(actual.pid, actual.start, '/private/reexec', actual.argv_sha)
                else:
                    values[4].actor_result = proc.ProcObservation('live_actor', '', 'HOST', baseline().boot,
                        actual, False, (), True, 2, (), 0, 0, True, 1)
            values[2].hook = later
            self.reject(lambda: values[0].resolve(values[-1]), 'actor_unknown')
            self.assertIsNotNone(values[-1].final_observation)
            self.assertIs(values[-1].postexec, actual); self.assertIsNone(values[-1].handle)
            self.assertEqual('post_exec_durable', json.loads(values[2].nodes[self.target_path(values)].data.decode('ascii'))['stage'])
            self.assertTrue(values[-2].released)

    def test_postpublish_r_s_transition_fresh_not_identity_replacement(self):
        values = self.released(); actual = self.final_actor(values)
        def later(io, operation, path, count):
            if operation == 'fsync' and path == RUN:
                values[4].child = actor(actual.pid, actual.start, actual.exe, actual.argv_sha,
                    ((actual.pid, actual.start, 'R'),))
        values[2].hook = later
        handle = values[0].resolve(values[-1])
        self.assertIs(handle.actor, actual)
        self.assertIsNot(values[-1].final_observation.actor, actual)
        self.assertEqual(actual.key(), values[-1].final_observation.actor.key())

    def test_close_only_original_sidecar_fds_not_child_or_store(self):
        values = self.released(); self.final_actor(values); values[0].resolve(values[-1])
        opened = list(values[0]._inventory); child_calls = list(values[5].calls)
        device = values[6]._device.fd
        status = values[0].close(); values[0].close()
        self.assertEqual(child_calls, values[5].calls)
        self.assertIn(device, values[2].handles); self.assertIn(PENDING, values[2].nodes)
        for ticket in opened: self.assertEqual(1, values[2].closed.count(ticket.fd))
        self.assertFalse(status['complete']); self.assertFalse(status['orphan_recovery'])
        self.reject(lambda: values[0].resolve(values[-1]), 'resource_pending')

    def test_baseexception_persist_keeps_pending_and_original_sidecar_refs(self):
        values = self.registered(); values[3].launch(values[-2])
        values[2].faults[('fsync', RUN + '/launch-watchdog.00000001.tmp')] = KeyboardInterrupt()
        # DirectChildOwner's established boundary maps callback BaseException
        # to fixed persist_unknown while retaining actual child/FD inventory.
        self.reject(lambda: values[0].release(values[-1]), 'component_error')
        self.assertTrue(values[-2].unknown); self.assertTrue(values[-1].unknown)
        self.assertIsNotNone(values[-1].preexec); self.assertTrue(values[0]._inventory)
        self.assert_no_gate(values)

    def test_exact_one_shot_resolve_bound_and_fixed_public_fields(self):
        values = self.released()
        for unused in range(16): self.assertIsNone(values[0].resolve(values[-1]))
        self.reject(lambda: values[0].resolve(values[-1]), 'already_attempted')
        value = json.dumps(values[0].status(), sort_keys=True)
        for text in (TOKEN, RUN, values[-3].boot, '/private/', 'argv_sha', 'target_ticket'):
            self.assertNotIn(text, value)
        self.assertFalse(values[0].status()['orphan_recovery'])

    def test_python35_ast_missing_modules_and_no_child_mutation(self):
        with open(launch.__file__, encoding='utf-8') as source: tree = ast.parse(source.read(), feature_version=(3, 5))
        with open(__file__, encoding='utf-8') as source: ast.parse(source.read(), feature_version=(3, 5))
        names = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        self.assertFalse({'fork', 'execve', 'kill', 'waitpid', 'mkdir', 'unlink_at', 'LOCK_UN', 'start', 'finish'} & names)
        imports = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        self.assertFalse({'json', 'fcntl', 'resource', 'socket', 'subprocess'} & imports)
        self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))


if __name__ == '__main__': unittest.main()
