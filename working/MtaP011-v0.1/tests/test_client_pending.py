"""HOST synthetic filesystem/process only; no actual /tmp or device access."""
import ast
import errno
import os
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime')))
import mta_client_pending as pending
import mta_client_coordination as coordination
import mta_client_proc as proc
import mta_p2p_client_init as core
from test_client_files import FakeIo, TOKEN, PENDING


class Clock(object):
    def __init__(self): self.value = 1.0
    def __call__(self): return self.value


class Io(FakeIo):
    FLAGS = dict(FakeIo.FLAGS, O_RDWR=2)

    def __init__(self):
        FakeIo.__init__(self)
        self.clock = Clock()
        self.flocks = []

    def flock(self, fd, flags):
        self.flocks.append((fd, flags))
        return (0, 0)

    def pause(self, seconds): self.clock.value += seconds

    def seek_start(self, fd):
        self.event('seek', self.handles[fd][0].path)
        self.handles[fd][1] = 0
        return 0


class Reader(object):
    def __init__(self):
        self.calls = 0
        self.actor = core.Actor(123, 300, '/usr/bin/python3', 'b' * 64, ((123, 300, 'S'),))
        self.boot = '11111111-1111-1111-1111-111111111111'
        self.kind, self.pending = 'live_actor', False

    def read_self(self):
        self.calls += 1
        return proc.ProcObservation(self.kind, 'synthetic', 'observed', self.boot, self.actor,
            False, (), True, 2, (), 12, 12, self.pending, 1)


class PendingTests(unittest.TestCase):
    def setUp(self):
        # Tripwire only the target's default I/O adapters. Patching global
        # os.stat breaks unittest's own traceback formatter on Windows.
        for cls in (pending._LinuxIo, coordination._LinuxIo):
            for name in ('validate', 'open_root', 'open_at', 'fstat', 'stat_at', 'close',
                         'read', 'write', 'fsync', 'seek_start', 'flock'):
                if hasattr(cls, name):
                    patcher = mock.patch.object(cls, name, side_effect=AssertionError('actual OS forbidden'))
                    patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(proc.ProcReader, 'read_self', side_effect=AssertionError('actual proc forbidden'))
        patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket'):
            patcher = mock.patch(target, side_effect=AssertionError('actual native forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)

    def make(self):
        io = Io()
        c = coordination.ClientCoordination(TOKEN, core.Identity('a' * 64), _io=io, _clock=io.clock)
        locks = c.acquire()
        self.addCleanup(c.close)
        reader = Reader()
        marker = pending.ClientPendingMarker(c, locks, _io=io, _reader=reader, _clock=io.clock)
        self.addCleanup(marker.close)
        return marker, io, reader, c, locks

    def reject(self, action, code):
        with self.assertRaises(pending.PendingError) as caught: action()
        self.assertEqual(code, caught.exception.code)
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertNotIn('/tmp', str(caught.exception))

    def test_constructor_pure_and_python35(self):
        marker, io, reader, _, _ = self.make()
        self.assertEqual(0, reader.calls)
        self.assertNotIn(PENDING, io.nodes)
        self.assertFalse(marker.status()['own_marker_admission'])
        with open(pending.__file__, encoding='utf-8') as source:
            tree = ast.parse(source.read(), feature_version=(3, 5))
        self.assertFalse({'unlink', 'rename', 'fork', 'kill', 'socket'} &
            {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)})
        self.assertFalse(any(isinstance(node, ast.Import) and any(n.name in ('json', 'fcntl', 'resource')
            for n in node.names) for node in ast.walk(tree)))

    def test_exact_locks_and_coordinator_only(self):
        marker, io, reader, c, locks = self.make()
        forged = coordination.LockSet(c._issuer, locks._device, locks._journal)
        self.reject(lambda: pending.ClientPendingMarker(c, forged, _io=io, _reader=reader), 'invalid_config')
        for timeout in (True, 0, float('nan'), float('inf')):
            self.reject(lambda: pending.ClientPendingMarker(c, locks, timeout=timeout), 'invalid_config')
        self.reject(lambda: pending.ClientPendingMarker(object(), locks), 'invalid_config')

    def test_create_verify_then_close_retains_exact_entry(self):
        marker, io, reader, _, _ = self.make()
        result = marker.create()
        self.assertEqual('retained_observed', result.marker_state)
        self.assertTrue(result.durable_created)
        self.assertTrue(result.owner_observed)
        self.assertFalse(result.resource_pending)
        original = io.nodes[PENDING]
        self.assertEqual(2, reader.calls)
        self.assertEqual(PENDING, io.opened[-1][0])
        self.assertEqual(0o600, io.opened[-1][2])
        self.assertEqual(2 | 64 | 128 | 131072 | 2048 | 524288, io.opened[-1][1])
        marker.verify()
        fd = marker._ticket.fd
        marker.close(); marker.close()
        self.assertEqual(1, io.closed.count(fd))
        self.assertIs(original, io.nodes[PENDING])
        self.assertTrue(marker._ticket.closed)
        self.reject(marker.verify, 'closed')
        self.reject(marker.create, 'already_attempted')

    def test_preexisting_entry_never_opened_or_overwritten(self):
        marker, io, reader, _, _ = self.make()
        original = io.add(PENDING, data=b'old-GO-or-unknown')
        before = list(io.opened)
        self.reject(marker.create, 'global_pending_blocked')
        self.assertEqual(before, io.opened)
        self.assertIs(original, io.nodes[PENDING])
        self.assertEqual(b'old-GO-or-unknown', original.data)

    def test_inode_substitution_identical_bytes_rejected(self):
        marker, io, reader, _, _ = self.make()
        marker.create()
        replacement = io.add(PENDING, data=io.nodes[PENDING].data)
        replacement.ino += 20
        self.reject(marker.verify, 'marker_changed')
        self.assertEqual('unknown', marker.status()['marker_state'])

    def test_owner_or_boot_change_rejects_without_file_mutation(self):
        for field in ('boot', 'actor'):
            marker, io, reader, _, _ = self.make()
            marker.create()
            before = len(io.opened)
            if field == 'boot': reader.boot = '22222222-2222-2222-2222-222222222222'
            else: reader.actor = core.Actor(123, 301, '/usr/bin/python3', 'b' * 64, ((123, 301, 'S'),))
            self.reject(marker.verify, 'owner_changed')
            self.assertEqual(before, len(io.opened))
            marker.close()

    def test_opaque_proc_or_pending_reader_does_not_create(self):
        for kind, unknown in (('opaque', False), ('live_actor', True)):
            marker, io, reader, _, _ = self.make()
            reader.kind, reader.pending = kind, unknown
            self.reject(marker.create, 'owner_unknown')
            self.assertNotIn(PENDING, io.nodes)

    def test_fsync_failure_retains_partial_file_no_retry(self):
        marker, io, _, _, _ = self.make()
        io.faults[('fsync', '/tmp')] = OSError(errno.EIO, 'synthetic')
        self.reject(marker.create, 'io_unknown')
        self.assertIn(PENDING, io.nodes)
        self.assertFalse(marker.status()['durable_created'])
        self.assertTrue(marker.status()['creation_unknown'])
        self.reject(marker.create, 'already_attempted')
        fd = marker._ticket.fd
        marker.close()
        self.assertEqual(1, io.closed.count(fd))

    def test_unknown_open_is_sticky_no_reopen_or_close_numeric_guess(self):
        marker, io, _, _, _ = self.make()
        io.unknown_open = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): marker.create()
        marker.close(); marker.close()
        self.assertTrue(marker.status()['resource_pending'])
        self.assertIsNone(marker._ticket.fd)
        self.assertFalse(marker._ticket.attempted)

    def test_close_error_never_erased_by_later_ebadf(self):
        marker, io, _, _, _ = self.make()
        marker.create()
        fd = marker._ticket.fd
        io.close_fail[fd] = OSError(errno.EINTR, 'synthetic')
        marker.close()
        io.handles.pop(fd)
        marker.close()
        self.assertEqual(1, io.closed.count(fd))
        self.assertTrue(marker.status()['resource_pending'])
        self.assertFalse(marker._ticket.closed)

    def test_coordination_close_blocks_further_reads_no_new_creation(self):
        marker, io, _, c, _ = self.make()
        marker.create()
        c.close()
        self.reject(marker.verify, 'io_unknown')
        self.assertIn(PENDING, io.nodes)

    def test_changed_bytes_same_inode_rejected(self):
        marker, io, _, _, _ = self.make()
        marker.create()
        io.nodes[PENDING].data = io.nodes[PENDING].data[:-2] + b'X\n'
        self.reject(marker.verify, 'marker_changed')

    def test_lock_entry_changed_does_not_read_marker_bytes(self):
        marker, io, _, _, locks = self.make()
        marker.create()
        io.add('/tmp/' + coordination.DEVICE_LOCK)
        before = sum(action == 'read' and path == PENDING for action, path in io.ops)
        self.reject(marker.verify, 'io_unknown')
        self.assertEqual(before, sum(action == 'read' and path == PENDING for action, path in io.ops))

    def test_create_race_does_not_overwrite_foreign_marker(self):
        marker, io, _, _, _ = self.make()
        def race(obj, action, path, count):
            if action == 'open' and path == PENDING:
                obj.add(PENDING, data=b'foreign')
        io.hook = race
        self.reject(marker.create, 'global_pending_blocked')
        self.assertEqual(b'foreign', io.nodes[PENDING].data)
        self.assertFalse(marker.status()['creation_unknown'])
        self.assertIsNone(marker._ticket.fd)

    def test_interrupt_after_creation_closes_original_once_without_unlink(self):
        marker, io, _, _, _ = self.make()
        io.faults[('write', PENDING)] = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): marker.create()
        fd = marker._ticket.fd
        marker.close(); marker.close()
        self.assertIn(PENDING, io.nodes)
        self.assertEqual(1, io.closed.count(fd))
        self.assertTrue(marker.status()['creation_unknown'])

    def test_owner_read_budget_expiration_prevents_creation(self):
        marker, io, reader, _, _ = self.make()
        original = reader.read_self
        def delayed():
            result = original()
            io.clock.value += 4
            return result
        reader.read_self = delayed
        self.reject(marker.create, 'expired')
        self.assertNotIn(PENDING, io.nodes)

    def test_closed_observation_has_no_clear_or_admission(self):
        marker, io, _, _, _ = self.make()
        obs = marker.create()
        with self.assertRaises(AttributeError): obs.marker_state = 'absent_observed'
        marker.close()
        # The narrow method exists; this closed observation grants no clear.
        self.assertTrue(marker.status()['marker_clear_implemented'])
        self.assertFalse(marker.status()['own_marker_admission'])
        self.assertFalse(hasattr(marker, 'clear'))
        self.assertFalse(hasattr(marker, 'finish'))


if __name__ == '__main__':
    unittest.main()
