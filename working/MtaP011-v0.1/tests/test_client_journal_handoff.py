"""HOST real component methods over FakeIO; no OS/OFD/exec/RF evidence."""
import ast
import errno
import os
import stat
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime')))
import mta_client_coordination as c
import mta_client_pending as p
import mta_client_files as f
import mta_client_proc as proc
import mta_p2p_client_init as core
from test_client_journal_transaction import CombinedIo
from test_client_files import TOKEN, RUN, BASE, TARGET, PENDING
from test_client_journal_codec import baseline, IDENTITY
from test_client_pending import Reader

JOURNAL = RUN + '/' + c.JOURNAL_LOCK
DEVICE = '/tmp/' + c.DEVICE_LOCK


class HandoffIo(CombinedIo):
    def __init__(self):
        CombinedIo.__init__(self)
        self.flock_results = []

    def flock(self, fd, flags):
        result = CombinedIo.flock(self, fd, flags)
        if self.flock_results:
            result = self.flock_results.pop(0)
            if isinstance(result, BaseException): raise result
        return result


class JournalHandoffTests(unittest.TestCase):
    def setUp(self):
        for cls in (c._LinuxIo, f._LinuxIo, p._LinuxIo):
            for name in ('validate', 'open_root', 'open_at', 'fstat', 'stat_at', 'close',
                         'read', 'write', 'fsync', 'seek_start', 'flock', 'rename_at'):
                if hasattr(cls, name):
                    patcher = mock.patch.object(cls, name, side_effect=AssertionError('actual OS forbidden'))
                    patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket'):
            patcher = mock.patch(target, side_effect=AssertionError('actual OS forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(proc.ProcReader, 'read_self', side_effect=AssertionError('actual proc forbidden'))
        patcher.start(); self.addCleanup(patcher.stop)

    def prepared(self, io=None):
        io, shared, epoch = io or HandoffIo(), threading.RLock(), object()
        coord = c.ClientCoordination(TOKEN, IDENTITY, _io=io, _clock=io.clock, _serialization_lock=shared)
        locks = coord.acquire()
        files = f.ClientJournalFiles(TOKEN, IDENTITY, _io=io, _clock=io.clock, _serialization_lock=shared)
        files.open()
        prepared = files.commit(None, core.Journal(IDENTITY, 'prepared', baseline(), 10.0))
        reader = Reader(); reader.boot = baseline().boot
        marker = p.ClientPendingMarker(coord, locks, _io=io, _reader=reader,
            _clock=io.clock, _serialization_lock=shared)
        marker.create()
        binding = marker.bind_files(files, prepared, epoch, shared)
        self.addCleanup(coord.close); self.addCleanup(files.close); self.addCleanup(marker.close)
        return coord, locks, files, marker, binding, epoch, io, reader

    def released(self, io=None):
        values = self.prepared(io)
        coord, locks, _, _, binding, epoch, _, _ = values
        released = coord.release_journal_handoff(locks, binding, epoch, 3.0)
        return values + (released,)

    def reject(self, action, code=None):
        with self.assertRaises(c.CoordinationError) as caught: action()
        if code is not None: self.assertEqual(code, caught.exception.code)
        self.assertIn(caught.exception.code, c._CODES)
        for value in (TOKEN, '/tmp/', 'private', 'wlan0'):
            self.assertNotIn(value, str(caught.exception))

    def no_more_journal_open(self, io, action):
        before = sum(path == JOURNAL for path, _, _, _ in io.opened)
        self.reject(action)
        self.assertEqual(before, sum(path == JOURNAL for path, _, _, _ in io.opened))

    def test_pure_types_python35_and_no_new_actions(self):
        # A's handoff still performs no unlink; only Pending's separate terminal entry may clear.
        for module in (c, p):
            with open(module.__file__, encoding='utf-8') as source:
                tree = ast.parse(source.read(), feature_version=(3, 5))
            self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))
            self.assertFalse({'unlink', 'mkdir', 'fork', 'dup', 'kill', 'waitpid', 'socket'} &
                {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)})
        for value in (c.ReleasedJournal(object(), object()), c.ReacquiredJournal(object(), object(), object())):
            self.assertNotIn(TOKEN, repr(value))
            with self.assertRaises(AttributeError): value.extra = True
        self.assertEqual(6, c.MAX_RESOURCES)

    def test_success_exact_device_seventh_existing_only_epoch_and_history(self):
        coord, old, files, marker, binding, epoch, io, _, released = self.released()
        device, marker_node = old._device, io.nodes[PENDING]
        self.assertEqual(6, len(coord._inventory))
        self.assertEqual(1, io.closed.count(old._journal.fd))
        self.assertIn(device.fd, io.handles)
        result = coord.reacquire_journal(released, 3.0)
        self.assertIs(type(result), c.ReacquiredJournal)
        self.assertIs(result.locks, coord._locks); self.assertIs(result.locks._device, device)
        self.assertIsNot(result.locks, old); self.assertIsNot(result.locks._journal, old._journal)
        self.assertIs(marker._locks, result.locks)
        self.assertIs(marker._binding_ticket.journal_epoch, coord._handoff.new_epoch)
        self.assertEqual(7, len(coord._inventory))
        new_open = [row for row in io.opened if row[0] == JOURNAL][-1]
        self.assertFalse(new_open[1] & (io.FLAGS['O_CREAT'] | io.FLAGS['O_EXCL']))
        self.assertEqual(0, new_open[2]); self.assertIs(io.nodes[PENDING], marker_node)
        self.assertIs(type(binding.verify(files, epoch)), p.PendingObservation)
        self.assertIsNotNone(files.read_current())
        self.assertTrue(coord.validate(result.locks))
        self.reject(lambda: coord.validate(old), 'invalid_lockset')
        before = list(io.opened), list(io.closed), list(io.flocks)
        self.assertEqual(7, len(coord.read_closed(old).observed))
        self.assertEqual(before, (io.opened, io.closed, io.flocks))
        marker.close(); files.close(); coord.close()
        self.assertTrue(coord.read_closed(old).complete())
        self.assertTrue(coord.read_closed(result.locks).complete())
        self.assertFalse(io.handles)
        self.assertEqual(len(io.closed), len(set(io.closed)))

    def test_released_ordinary_reads_refuse_without_revoking_handoff(self):
        coord, old, files, marker, binding, epoch, io, _, released = self.released()
        before = list(io.opened), list(io.closed), list(io.flocks)
        self.reject(lambda: coord.validate(old), 'journal_released')
        self.reject(lambda: coord.read_pending(old), 'journal_released')
        with self.assertRaises(p.PendingError): binding.verify(files, epoch)
        with self.assertRaises(f.ClientFileError): files.read_current()
        self.assertEqual(before, (io.opened, io.closed, io.flocks))
        self.assertFalse(marker.status()['local_binding_issued'])
        self.assertFalse(marker._binding_ticket.unknown)
        coord.reacquire_journal(released, 3.0)
        self.assertTrue(marker.status()['local_binding_issued'])

    def test_forged_release_epoch_binding_and_lockset_zero_io(self):
        coord, old, _, marker, binding, epoch, io, _ = self.prepared()
        forged_binding = p.OwnedMarkerBinding(binding._issuer, marker, coord, binding._files,
            binding._prepared, epoch, binding._serialization_lock)
        before = list(io.ops), list(io.closed)
        for args in ((old, binding, object()), (old, forged_binding, epoch),
                (c.LockSet(coord._issuer, old._device, old._journal), binding, epoch)):
            self.reject(lambda args=args: coord.release_journal_handoff(*(args + (3.0,))))
        self.assertEqual(before, (io.ops, io.closed)); self.assertIsNone(coord._handoff)

    def test_forged_released_receipt_zero_io(self):
        coord, _, _, _, _, _, io, _, receipt = self.released()
        before = list(io.ops)
        copied = c.ReleasedJournal(coord._issuer, receipt._context)
        self.reject(lambda: coord.reacquire_journal(copied, 3.0), 'invalid_handoff')
        self.assertEqual(before, io.ops); self.assertFalse(coord._handoff.reacquire_attempted)

    def test_only_one_handoff_attempt_and_no_second_generation(self):
        coord, _, _, _, binding, epoch, io, _, receipt = self.released()
        result = coord.reacquire_journal(receipt, 3.0)
        before = list(io.ops)
        self.reject(lambda: coord.reacquire_journal(receipt, 3.0))
        self.reject(lambda: coord.release_journal_handoff(result.locks, binding, epoch, 3.0), 'handoff_attempted')
        self.assertEqual(before, io.ops); self.assertEqual(7, len(coord._inventory))

    def test_old_release_does_not_issue_handoff_or_allow_reopen(self):
        coord, old, _, _, binding, epoch, io, _ = self.prepared()
        coord.release_journal(old)
        self.assertIsNone(coord._handoff)
        self.no_more_journal_open(io, lambda: coord.reacquire_journal(c.ReleasedJournal(coord._issuer, object()), 3.0))
        self.no_more_journal_open(io, lambda: coord.release_journal_handoff(old, binding, epoch, 3.0))

    def test_deadline_exact_type_range_checked_before_handoff(self):
        coord, old, _, _, binding, epoch, io, _ = self.prepared()
        for deadline in (True, 10 ** 1000, float('inf'), float('nan'), -1, 1, 22):
            before = list(io.ops), list(io.closed)
            self.reject(lambda: coord.release_journal_handoff(old, binding, epoch, deadline))
            self.assertEqual(before, (io.ops, io.closed)); self.assertIsNone(coord._handoff)

    def test_release_unknown_close_never_permits_reacquire(self):
        coord, old, _, _, binding, epoch, io, _ = self.prepared()
        io.close_fail[old._journal.fd] = OSError(errno.EINTR, 'private')
        self.reject(lambda: coord.release_journal_handoff(old, binding, epoch, 3.0), 'close_unverified')
        self.assertIsNone(coord._handoff.released); self.assertTrue(coord.status()['resource_pending'])
        del io.close_fail[old._journal.fd]; del io.handles[old._journal.fd]
        coord.close(); coord.close()
        self.assertEqual(1, io.closed.count(old._journal.fd))
        self.assertFalse(coord.read_closed(old).complete())

    def test_release_consumed_but_raised_unknown_sticky(self):
        coord, old, _, _, binding, epoch, io, _ = self.prepared()
        close = io.close
        def consumed(fd):
            close(fd)
            if fd == old._journal.fd: raise MemoryError('private')
        io.close = consumed
        self.reject(lambda: coord.release_journal_handoff(old, binding, epoch, 3.0))
        self.assertFalse(old._journal.closed); self.assertTrue(coord.status()['resource_pending'])
        coord.close(); coord.close()
        self.assertEqual(1, io.closed.count(old._journal.fd))

    def test_missing_or_changed_journal_no_create(self):
        for change in ('missing', 'inode', 'mode', 'links', 'nonempty'):
            coord, old, _, _, _, _, io, _, receipt = self.released()
            node = io.nodes[JOURNAL]
            if change == 'missing': del io.nodes[JOURNAL]
            elif change == 'inode': node.ino += 1
            elif change == 'mode': node.mode = stat.S_IFREG | 0o666
            elif change == 'links': node.links = 2
            else: node.data = b'x'
            self.no_more_journal_open(io, lambda: coord.reacquire_journal(receipt, 3.0))
            self.assertIn(old._device.fd, io.handles)
            self.assertEqual(6, len(coord._inventory))

    def test_changed_directory_or_device_no_new_open(self):
        for path in (RUN, BASE, DEVICE):
            coord, _, _, _, _, _, io, _, receipt = self.released()
            io.nodes[path].ino += 1
            self.no_more_journal_open(io, lambda: coord.reacquire_journal(receipt, 3.0))

    def test_marker_same_bytes_foreign_inode_or_missing_no_new_open(self):
        for change in ('inode', 'missing', 'bytes'):
            coord, _, _, _, _, _, io, _, receipt = self.released()
            if change == 'missing': del io.nodes[PENDING]
            elif change == 'inode': io.nodes[PENDING].ino += 1
            else: io.nodes[PENDING].data += b' '
            self.no_more_journal_open(io, lambda: coord.reacquire_journal(receipt, 3.0))

    def test_owner_start_tasks_boot_change_no_new_open(self):
        for change in ('start', 'tasks', 'boot', 'zombie'):
            coord, _, _, _, _, _, io, reader, receipt = self.released()
            actor = reader.actor
            if change == 'boot': reader.boot = '00000000-0000-0000-0000-000000000001'
            else:
                reader.actor = core.Actor(actor.pid, actor.start + (change == 'start'), actor.exe, actor.argv_sha,
                    ((actor.pid, actor.start + (change == 'start'), 'Z' if change == 'zombie' else 'S'),) +
                    (((124, 301, 'S'),) if change == 'tasks' else ()))
            self.no_more_journal_open(io, lambda: coord.reacquire_journal(receipt, 3.0))

    def test_participant_closed_or_unknown_no_new_open(self):
        for change in ('marker', 'files', 'coord', 'write_unknown'):
            coord, _, files, marker, _, _, io, _, receipt = self.released()
            if change == 'marker': marker.close()
            elif change == 'files': files.close()
            elif change == 'coord': coord.close()
            else: files._write_pending = True
            self.no_more_journal_open(io, lambda: coord.reacquire_journal(receipt, 3.0))

    def test_open_unknown_retains_exact_creator_and_seventh_ticket(self):
        coord, old, _, _, _, _, io, _, receipt = self.released()
        io.unknown_open = MemoryError('private')
        self.reject(lambda: coord.reacquire_journal(receipt, 3.0))
        ticket = coord._handoff.new_ticket
        self.assertIs(ticket, coord._inventory[-1]); self.assertIs(ticket.io, io)
        self.assertIsNone(ticket.fd); self.assertTrue(ticket.opening_unknown)
        self.assertEqual(7, len(coord._inventory)); self.assertIn(old._device.fd, io.handles)
        attempts = io.counts[('open', JOURNAL)]
        self.reject(lambda: coord.reacquire_journal(receipt, 3.0))
        self.assertEqual(attempts, io.counts[('open', JOURNAL)])

    def test_open_allocated_nonreturn_keeps_unknown_no_guess(self):
        coord, _, _, _, _, _, io, _, receipt = self.released()
        original = io.open_at
        def allocated(parent, name, flags, mode=0):
            fd = original(parent, name, flags, mode)
            if name == c.JOURNAL_LOCK: raise MemoryError('private')
            return fd
        io.open_at = allocated
        self.reject(lambda: coord.reacquire_journal(receipt, 3.0))
        actual = io.opened[-1][3]
        self.assertIsNone(coord._handoff.new_ticket.fd)
        coord.close(); self.assertIn(actual, io.handles); self.assertNotIn(actual, io.closed)

    def test_malformed_returned_fd_kept_not_closed_as_number(self):
        coord, _, _, _, _, _, io, _, receipt = self.released()
        returned = object()
        io.open_at = lambda *args: returned
        self.reject(lambda: coord.reacquire_journal(receipt, 3.0))
        self.assertIs(coord._handoff.new_ticket.fd, returned)
        coord.close(); self.assertNotIn(returned, io.closed)

    def test_flock_known_busy_eintr_then_acquire_one_open(self):
        coord, _, _, _, _, _, io, _, receipt = self.released()
        io.flock_results = [(-1, errno.EAGAIN), (-1, errno.EINTR), (0, 0)]
        result = coord.reacquire_journal(receipt, 3.0)
        self.assertEqual('active', coord._handoff.stage)
        self.assertEqual(2, sum(path == JOURNAL for path, _, _, _ in io.opened))
        self.assertTrue(all(flags == c.LOCK_FLAGS for _, flags in io.flocks))
        self.assertIs(result.locks._device, coord._handoff.device)

    def test_flock_unknown_closes_known_new_once_no_retry(self):
        for error in (MemoryError('private'), (True, 0), (-1, True), (0, 1), (-1, 0)):
            coord, old, _, _, _, _, io, _, receipt = self.released()
            io.flock_results = [error]
            self.reject(lambda: coord.reacquire_journal(receipt, 3.0))
            new = coord._handoff.new_ticket
            self.assertTrue(coord.status()['resource_pending'])
            self.assertEqual(1, io.closed.count(new.fd))
            self.assertIn(old._device.fd, io.handles)
            coord.close(); self.assertEqual(1, io.closed.count(new.fd))

    def test_busy_timeout_once_no_retry_no_device_close(self):
        coord, old, _, _, _, _, io, _, receipt = self.released()
        io.flock_results = [(-1, errno.EAGAIN)] * 50
        self.reject(lambda: coord.reacquire_journal(receipt, 1.02), 'deadline')
        new = coord._handoff.new_ticket
        self.assertEqual(1, io.closed.count(new.fd)); self.assertIn(old._device.fd, io.handles)
        self.assertEqual(2, sum(path == JOURNAL for path, _, _, _ in io.opened))
        self.reject(lambda: coord.reacquire_journal(receipt, 3.0))

    def test_postopen_inode_substitution_closes_new_not_device(self):
        coord, old, _, _, _, _, io, _, receipt = self.released()
        def hook(io, operation, path, count):
            if operation == 'open' and path == JOURNAL: io.nodes[JOURNAL].ino += 1
        io.hook = hook
        self.reject(lambda: coord.reacquire_journal(receipt, 3.0), 'lock_changed')
        self.assertTrue(coord._handoff.new_ticket.closed); self.assertIn(old._device.fd, io.handles)

    def test_publish_postswap_failure_keeps_both_locksets_and_partial_epoch(self):
        coord, old, files, marker, binding, epoch, io, _, receipt = self.released()
        def hook(io, operation, path, count):
            if coord._handoff.stage == 'committing': raise MemoryError('private')
        io.hook = hook
        self.reject(lambda: coord.reacquire_journal(receipt, 3.0))
        context = coord._handoff
        self.assertEqual('partial', context.stage); self.assertTrue(context.unknown)
        self.assertIs(coord._locks, context.new_locks); self.assertIs(marker._locks, context.new_locks)
        self.assertEqual([old, context.new_locks], coord._locksets)
        self.assertIs(marker._binding_ticket.journal_epoch, context.new_epoch)
        self.assertIsNotNone(context.reacquired)
        self.assertTrue(context.new_ticket.closed)
        with self.assertRaises(p.PendingError): binding.verify(files, epoch)
        self.reject(lambda: coord.validate(context.new_locks), 'journal_released')
        self.assertFalse(coord.read_closed(old).complete())

    def test_every_handoff_io_under_shared_outer_domain(self):
        coord, _, _, marker, _, _, io, _, receipt = self.released()
        shared = coord._serialization_lock
        def hook(io, operation, path, count): self.assertTrue(shared._is_owned())
        io.hook = hook
        result = coord.reacquire_journal(receipt, 3.0)
        self.assertIs(marker._serialization_lock, shared)
        coord.validate(result.locks)

    def test_owned_numeric_fd_reuse_does_not_reclose_new_as_old(self):
        coord, old, _, _, _, _, io, _, receipt = self.released()
        io.fd = old._journal.fd - 1
        result = coord.reacquire_journal(receipt, 3.0)
        new = result.locks._journal
        self.assertEqual(old._journal.fd, new.fd); self.assertIsNot(old._journal, new)
        self.assertEqual(1, io.closed.count(new.fd))
        coord.close(); coord.close()
        self.assertEqual(2, io.closed.count(new.fd))  # Two distinct actual opens.
        self.assertTrue(coord.read_closed(old).complete())

    def test_ordinary_open_budget_stays_six_after_handoff(self):
        coord, _, _, _, _, _, io, _, receipt = self.released()
        coord.reacquire_journal(receipt, 3.0)
        before = list(io.opened)
        self.reject(lambda: coord._open(None, None, 0), 'resource_budget')
        self.assertEqual(before, io.opened)

    def test_malformed_live_fd_alias_never_closes_original_as_new(self):
        for owner in ('device', 'files_anchor', 'marker'):
            coord, old, files, marker, _, _, io, _, receipt = self.released()
            original = old._device if owner == 'device' else \
                (files._inventory[0] if owner == 'files_anchor' else marker._ticket)
            io.open_at = lambda *args: original.fd
            self.reject(lambda: coord.reacquire_journal(receipt, 3.0), 'invalid_descriptor')
            ticket = coord._handoff.new_ticket
            self.assertEqual(original.fd, ticket.fd); self.assertTrue(ticket.opening_unknown)
            self.assertIn(original.fd, io.handles); self.assertNotIn(original.fd, io.closed)
            marker.close(); files.close(); coord.close(); coord.close()
            self.assertEqual(1, io.closed.count(original.fd))
            self.assertTrue(coord.status()['resource_pending'])


if __name__ == '__main__': unittest.main()
