"""Synthetic filesystem/process and threading only, never OS/WSL/RF admission."""
import ast
import errno
import os
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime')))
import mta_client_coordination as c
import mta_client_files as f
import mta_client_pending as p
import mta_client_proc as proc
import mta_p2p_client_init as core
from test_client_files import TOKEN, PENDING, TARGET, RUN
from test_client_pending import Io, Reader
from test_client_journal_codec import record, IDENTITY, BOOT


class OwnedMarkerTests(unittest.TestCase):
    def setUp(self):
        for cls in (c._LinuxIo, f._LinuxIo, p._LinuxIo):
            for name in ('validate', 'open_root', 'open_at', 'stat_at', 'fstat',
                         'read', 'write', 'seek_start', 'fsync', 'rename_at', 'close', 'flock'):
                if hasattr(cls, name):
                    patcher = mock.patch.object(cls, name, side_effect=AssertionError('actual OS forbidden'))
                    patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket'):
            patcher = mock.patch(target, side_effect=AssertionError('actual native forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(proc.ProcReader, 'read_self', side_effect=AssertionError('actual proc forbidden'))
        patcher.start(); self.addCleanup(patcher.stop)

    def make(self, shared=True, create=True):
        io, epoch, domain = Io(), object(), threading.RLock()
        kw = {'_serialization_lock': domain} if shared else {}
        coord = c.ClientCoordination(TOKEN, IDENTITY, _io=io, _clock=io.clock, **kw)
        locks = coord.acquire()
        jf = f.ClientJournalFiles(TOKEN, IDENTITY, _io=io, _clock=io.clock, **kw)
        jf.open()
        prepared = jf.commit(None, record('prepared'))
        reader = Reader(); reader.boot = BOOT
        marker = p.ClientPendingMarker(coord, locks, _io=io, _reader=reader, _clock=io.clock, **kw)
        self.addCleanup(coord.close); self.addCleanup(jf.close); self.addCleanup(marker.close)
        if create: marker.create()
        return marker, jf, coord, locks, prepared, epoch, domain, io, reader

    def bind(self, values):
        marker, jf, _, _, prepared, epoch, shared, _, _ = values
        return marker.bind_files(jf, prepared, epoch, shared)

    def reject(self, code, call):
        with self.assertRaises(p.PendingError) as caught: call()
        self.assertEqual(code, caught.exception.code)
        self.assertNotIn(TOKEN, str(caught.exception)); self.assertNotIn('/tmp', str(caught.exception))

    def test_pure_shared_constructors_and_exact_lock_type(self):
        io, shared = Io(), threading.RLock()
        coord = c.ClientCoordination(TOKEN, IDENTITY, _io=io, _serialization_lock=shared)
        jf = f.ClientJournalFiles(TOKEN, IDENTITY, _io=io, _serialization_lock=shared)
        self.assertEqual([], io.ops); self.assertIs(shared, coord._serialization_lock)
        self.assertIs(shared, jf._serialization_lock)
        for cls in (c.ClientCoordination, f.ClientJournalFiles):
            for lock in (True, object(), threading.Lock()):
                with self.assertRaises(ValueError): cls(TOKEN, IDENTITY, _serialization_lock=lock)

    def test_issue_exact_private_registry_and_readback_only(self):
        values = self.make(); marker, jf, coord, _, prepared, epoch, shared, _, _ = values
        binding = self.bind(values)
        self.assertIs(type(binding), p.OwnedMarkerBinding)
        self.assertIs(binding._prepared, prepared); self.assertIs(binding._epoch, epoch)
        self.assertIs(binding, coord._owned_marker_binding); self.assertIs(binding, jf._owned_marker_binding)
        self.assertTrue(all(obj._serialization_lock is shared for obj in (marker, jf, coord)))
        observed = binding.verify(jf, epoch)
        self.assertIs(type(observed), p.PendingObservation)
        self.assertEqual('retained_observed', observed.marker_state); self.assertTrue(observed.owner_observed)
        self.assertFalse(observed.resource_pending)
        with self.assertRaises(AttributeError): binding._epoch = object()
        for item in (TOKEN, '/tmp', IDENTITY.candidate_sha): self.assertNotIn(item, repr(binding))
        self.assertFalse(marker.status()['own_marker_admission']); self.assertFalse(coord.status()['mutation_admission'])
        self.assertFalse(jf.status()['mutation_admission'])

    def test_coordination_reads_real_present_entry_not_fake_enoent(self):
        values = self.make(); _, _, coord, locks, _, _, _, io, reader = values
        self.bind(values); before = reader.calls
        self.assertTrue(coord.validate(locks)); value = coord.read_pending(locks)
        self.assertFalse(value['entry_absent_observed']); self.assertTrue(value['own_entry_observed'])
        self.assertIn(PENDING, io.nodes); self.assertGreater(reader.calls, before)
        self.assertTrue(any(action == 'read' and path == PENDING for action, path in io.ops))

    def test_files_cas_renames_allowed_after_prepared_binding(self):
        values = self.make(); marker, jf, _, _, prepared, epoch, _, io, _ = values
        binding = self.bind(values)
        next_record = record('prepared').replace(deadline=25.0)
        current = jf.commit(prepared, next_record)
        self.assertNotEqual(prepared.metadata[1], current.metadata[1]); self.assertEqual(2, current._generation)
        self.assertEqual(current.data, jf.read_current().data)
        self.assertTrue(binding.verify(jf, epoch).owner_observed); self.assertIs(binding._prepared, prepared)
        self.assertIn(PENDING, io.nodes); self.assertTrue(marker.status()['local_binding_issued'])

    def test_unbound_own_marker_is_still_default_blocker(self):
        marker, jf, coord, locks, prepared, _, _, io, _ = self.make()
        opened = len(io.opened)
        with self.assertRaises(c.CoordinationError): coord.validate(locks)
        with self.assertRaises(f.ClientFileError): jf.commit(prepared, record('prepared'))
        self.assertEqual(opened, len(io.opened)); self.assertIsNone(coord._owned_marker_binding)
        # Default existing readonly read_current behavior is not expanded to writes.
        self.assertEqual(prepared.data, jf.read_current().data)
        self.assertFalse(marker.status()['own_marker_admission'])

    def test_default_domains_transition_to_one_shared_lock(self):
        values = self.make(shared=False); marker, jf, coord, _, _, epoch, shared, _, _ = values
        binding = self.bind(values)
        self.assertTrue(all(obj._serialization_lock is shared for obj in (marker, jf, coord)))
        self.assertTrue(binding.verify(coord, epoch).owner_observed)

    def test_explicit_mismatched_domain_rejected_before_acquiring_it(self):
        values = self.make(); marker, jf, _, _, prepared, epoch, _, io, _ = values
        before = len(io.ops)
        self.reject('invalid_binding', lambda: marker.bind_files(jf, prepared, epoch, threading.RLock()))
        self.assertEqual(before, len(io.ops)); self.assertFalse(marker._binding_attempted)

    def test_pending_observation_bool_or_foreign_epoch_is_not_binding(self):
        for index in (0, 1, 2):
            values = self.make(); marker, jf, _, _, prepared, epoch, shared, _, _ = values
            args = [jf, prepared, epoch, shared]
            args[index] = (marker.verify(), True, False)[index]
            self.reject('invalid_binding', lambda: marker.bind_files(*args))
            self.assertFalse(marker.status()['local_binding_issued'])

    def test_foreign_files_issuer_or_forged_equal_canonical_rejected(self):
        for variant in ('forged', 'issuer', 'generation'):
            values = self.make(); marker, jf, _, _, prepared, epoch, shared, _, _ = values
            changed = f.CanonicalRecord(prepared.journal, prepared.data, prepared.metadata,
                object() if variant == 'issuer' else prepared._issuer,
                prepared._generation - 1 if variant == 'generation' else prepared._generation)
            self.reject('invalid_binding', lambda: marker.bind_files(jf, changed, epoch, shared))
            self.assertIsNot(changed, prepared); self.assertFalse(marker.status()['local_binding_issued'])

    def test_initial_not_prepared_stage_rejected(self):
        values = self.make(create=False); marker, jf, _, _, prepared, epoch, shared, _, _ = values
        other = jf.commit(prepared, record('new')); marker.create()
        self.reject('invalid_binding', lambda: marker.bind_files(jf, other, epoch, shared))

    def test_prepared_full_metadata_substitution_rejected(self):
        values = self.make(); marker, jf, _, _, prepared, epoch, shared, io, _ = values
        io.nodes[TARGET].ino += 100
        self.reject('prepared_changed', lambda: marker.bind_files(jf, prepared, epoch, shared))
        self.reject('binding_attempted', lambda: marker.bind_files(jf, prepared, epoch, shared))

    def test_prepared_bytes_change_even_same_core_key_rejected(self):
        values = self.make(); marker, jf, _, _, prepared, epoch, shared, io, _ = values
        base = prepared.journal.baseline
        old = base.stock_actors[0]
        changed = core.Actor(old.pid, old.start, old.exe, old.argv_sha,
            tuple((pid, start, 'S' if state != 'S' else 'R') for pid, start, state in old.tasks))
        snapshot = core.Snapshot(base.boot, base.stock_hashes, (changed,) + base.stock_actors[1:],
            base.station, base.station_state_sha, base.station_frequency, base.interfaces, base.ipv4,
            base.ipv6_addresses, base.ipv6_routes, base.station_completed)
        replacement = prepared.journal.replace(baseline=snapshot)
        self.assertEqual(prepared.journal.key(), replacement.key())
        from mta_client_journal_codec import encode_journal
        io.nodes[TARGET].data = encode_journal(replacement)
        self.reject('prepared_changed', lambda: marker.bind_files(jf, prepared, epoch, shared))

    def test_initial_marker_requires_durable_create(self):
        values = self.make(create=False); marker, jf, _, _, prepared, epoch, shared, _, _ = values
        self.reject('binding_unknown', lambda: marker.bind_files(jf, prepared, epoch, shared))
        self.assertFalse(marker.status()['local_binding_issued'])

    def test_initial_current_boot_must_match_prepared(self):
        values = self.make(); marker, jf, _, _, prepared, epoch, shared, _, _ = values
        marker._boot = '11111111-1111-1111-1111-111111111111'
        self.reject('owner_changed', lambda: marker.bind_files(jf, prepared, epoch, shared))

    def test_fresh_marker_same_bytes_different_inode_revokes_binding(self):
        values = self.make(); marker, jf, _, _, prepared, _, _, io, _ = values
        self.bind(values); original = io.nodes[PENDING]
        replacement = io.add(PENDING, data=original.data); replacement.ino = original.ino + 99
        opened = len(io.opened)
        with self.assertRaises(f.ClientFileError): jf.commit(prepared, record('prepared'))
        self.assertEqual(opened, len(io.opened)); self.assertFalse(marker.status()['local_binding_issued'])

    def test_fresh_marker_bytes_owner_boot_and_metadata_rejected(self):
        for change in ('bytes', 'owner', 'boot', 'mode'):
            values = self.make(); marker, jf, _, _, _, epoch, _, io, reader = values
            binding = self.bind(values)
            if change == 'bytes': io.nodes[PENDING].data = b'old-GO-or-foreign'
            elif change == 'owner': reader.actor = core.Actor(123, 301, '/usr/bin/python3', 'b' * 64, ((123, 301, 'S'),))
            elif change == 'boot': reader.boot = '11111111-1111-1111-1111-111111111111'
            else: io.nodes[PENDING].mode |= 0o022
            with self.assertRaises(p.PendingError): binding.verify(jf, epoch)
            self.assertFalse(marker.status()['local_binding_issued'])

    def test_missing_owned_entry_does_not_use_enoent_default_path(self):
        values = self.make(); marker, jf, coord, locks, _, _, _, io, _ = values
        self.bind(values); del io.nodes[PENDING]
        with self.assertRaises(c.CoordinationError): coord.read_pending(locks)
        with self.assertRaises(f.ClientFileError): jf.read_current()
        self.assertFalse(marker.status()['local_binding_issued'])

    def test_exact_consumer_epoch_and_registry_required(self):
        values = self.make(); marker, jf, _, _, prepared, epoch, shared, _, _ = values
        binding = self.bind(values)
        for consumer, supplied in ((object(), epoch), (jf, object()), (jf, True)):
            self.reject('invalid_binding', lambda: binding.verify(consumer, supplied))
        forged = p.OwnedMarkerBinding(marker._issuer, marker, marker._coordination, jf, prepared, epoch, shared)
        self.reject('invalid_binding', lambda: forged.verify(jf, epoch))
        self.assertTrue(binding.verify(jf, epoch).owner_observed)

    def test_consumer_registered_epoch_or_binding_cannot_be_replaced(self):
        for change in ('epoch', 'binding'):
            values = self.make(); _, jf, _, _, _, epoch, _, _, _ = values
            binding = self.bind(values)
            if change == 'epoch': jf._owned_marker_epoch = object()
            else: jf._owned_marker_binding = True
            self.reject('invalid_binding', lambda: binding.verify(jf, epoch))

    def test_directory_anchor_disagreement_or_replacement_rejected(self):
        values = self.make(); marker, jf, _, _, _, epoch, _, io, _ = values
        binding = self.bind(values); io.nodes[RUN].ino += 99
        with self.assertRaises(p.PendingError): binding.verify(jf, epoch)
        self.assertFalse(marker.status()['local_binding_issued'])

    def test_released_or_changed_original_lock_refuses_binding(self):
        for change in ('release', 'swap'):
            values = self.make(); marker, jf, coord, locks, _, epoch, _, io, _ = values
            binding = self.bind(values)
            if change == 'release': coord.release_journal(locks)
            else: io.nodes['/tmp/' + c.DEVICE_LOCK].ino += 19
            with self.assertRaises(p.PendingError): binding.verify(jf, epoch)
            self.assertFalse(marker.status()['local_binding_issued'])

    def test_any_participant_closed_or_unknown_blocks_but_cleanup_still_once(self):
        for change in ('marker', 'files', 'coord', 'unknown'):
            values = self.make(); marker, jf, coord, _, _, epoch, _, io, _ = values
            binding = self.bind(values)
            if change == 'marker': marker.close()
            elif change == 'files': jf.close()
            elif change == 'coord': coord.close()
            else: jf._resource_pending = True
            with self.assertRaises(p.PendingError): binding.verify(jf, epoch)
            marker.close(); jf.close(); coord.close()
            closed = list(io.closed)
            marker.close(); jf.close(); coord.close()
            self.assertEqual(closed, io.closed); self.assertIn(PENDING, io.nodes)

    def test_partial_install_failure_is_retained_and_blocks_rebind(self):
        values = self.make(); marker, jf, coord, _, prepared, epoch, shared, io, _ = values
        reads = [0]
        def fail_after_install(obj, action, path, count):
            if action == 'read' and path == PENDING and coord._owned_marker_binding is not None:
                reads[0] += 1
                raise KeyboardInterrupt()
        io.hook = fail_after_install
        with self.assertRaises(KeyboardInterrupt): self.bind(values)
        io.hook = None
        self.assertGreater(reads[0], 0); self.assertIsNotNone(marker._binding_ticket.binding)
        self.assertIs(coord._owned_marker_binding, jf._owned_marker_binding)
        self.assertFalse(marker.status()['local_binding_issued']); self.assertTrue(marker._binding_ticket.unknown)
        self.reject('binding_attempted', lambda: marker.bind_files(jf, prepared, epoch, shared))
        with self.assertRaises(f.ClientFileError): jf.commit(prepared, record('prepared'))

    def test_guard_expiry_revokes_and_does_not_extend_files_budget(self):
        values = self.make(); marker, jf, _, _, prepared, _, _, io, reader = values
        self.bind(values)
        original = reader.read_self
        def late():
            result = original(); io.clock.value += 4; return result
        reader.read_self = late
        with self.assertRaises(f.ClientFileError): jf.commit(prepared, record('prepared'))
        self.assertFalse(marker.status()['local_binding_issued'])

    def test_every_bound_io_and_close_has_shared_outer_domain(self):
        values = self.make(); marker, jf, coord, locks, prepared, _, shared, io, _ = values
        self.bind(values)
        def owned(obj, action, path, count): self.assertTrue(shared._is_owned())
        io.hook = owned
        coord.validate(locks); jf.commit(prepared, record('prepared').replace(deadline=20))
        jf.read_current(); marker.verify(); marker.close(); jf.close(); coord.close()

    def test_concurrent_marker_verify_coord_guard_and_files_read_do_not_abba(self):
        values = self.make(); marker, jf, coord, locks, _, _, _, _, _ = values
        self.bind(values); barrier, errors = threading.Barrier(3), []
        def work(action):
            try:
                barrier.wait(timeout=2)
                for _ in range(5): action()
            except BaseException as error: errors.append(type(error).__name__)
        threads = [threading.Thread(target=work, args=(action,), daemon=True)
            for action in (marker.verify, lambda: coord.validate(locks), jf.read_current)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(timeout=3)
        self.assertFalse(any(thread.is_alive() for thread in threads)); self.assertEqual([], errors)

    def test_old_queued_domain_recaptures_after_binding_transition(self):
        values = self.make(shared=False); marker, jf, _, _, _, _, shared, io, _ = values
        entered, released, errors = threading.Event(), threading.Event(), []
        original = jf._serialization_lock
        class OldDomain(object):
            def acquire(self):
                entered.set(); released.wait(timeout=2); original.acquire()
            def release(self): original.release()
        jf._serialization_lock = OldDomain()
        def reader():
            try: jf.read_current()
            except BaseException as error: errors.append(type(error).__name__)
        thread = threading.Thread(target=reader, daemon=True); thread.start(); self.assertTrue(entered.wait(1))
        # Replace the unclaimed old domain under its actual inner lock, exactly
        # the bind transition rule. The old queued operation must recapture it.
        with jf._lock: jf._serialization_lock = shared
        io.hook = lambda obj, action, path, count: self.assertTrue(shared._is_owned())
        released.set(); thread.join(timeout=3)
        self.assertFalse(thread.is_alive()); self.assertEqual([], errors)
        io.hook = None

    def test_python35_all_changed_sources_and_no_new_clear_rf_operations(self):
        # The new fixed terminal clear is file-only; generic unlink/RF remains forbidden.
        for module in (c, f, p):
            with open(module.__file__, encoding='utf-8') as handle: tree = ast.parse(handle.read(), feature_version=(3, 5))
            attrs = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
            self.assertFalse({'unlink', 'mkdir', 'fork', 'kill', 'socket', 'waitpid'} & attrs)
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        values = self.make(); marker = values[0]; self.bind(values)
        for name in ('clear', 'finish', 'restore', 'start'): self.assertFalse(hasattr(marker, name))
        self.assertTrue(hasattr(marker, 'clear_terminal'))


if __name__ == '__main__': unittest.main()
