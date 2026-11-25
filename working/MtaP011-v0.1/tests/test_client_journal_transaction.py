"""HOST actual component composition over FakeIO; no OS locks/proc/network."""
import ast
import errno
import os
import stat
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime')))
import mta_client_journal_transaction as transaction
import mta_client_coordination as coordination
import mta_client_files as files
import mta_client_pending as pending
import mta_client_journal_codec as codec
import mta_client_proc as proc
import mta_p2p_client_init as core
from test_client_files import FakeIo, TOKEN, BASE, RUN, TARGET, PENDING
from test_client_pending import Reader
from test_client_journal_codec import baseline, IDENTITY


class Clock(object):
    def __init__(self): self.value = 1.0
    def __call__(self): return self.value


class CombinedIo(FakeIo):
    FLAGS = dict(FakeIo.FLAGS, O_RDWR=2)

    def __init__(self):
        FakeIo.__init__(self)
        self.clock, self.flocks = Clock(), []

    def flock(self, fd, flags):
        self.event('flock', self.handles[fd][0].path)
        self.flocks.append((fd, flags))
        return (0, 0)

    def pause(self, seconds): self.clock.value += seconds

    def seek_start(self, fd):
        self.event('seek', self.handles[fd][0].path)
        self.handles[fd][1] = 0
        return 0


def changed_baseline(state='R', fingerprint=None):
    original = baseline()
    actors = list(original.stock_actors)
    actor = actors[0]
    tasks = tuple((pid, start, state if pid == actor.pid else old) for pid, start, old in actor.tasks)
    actors[0] = core.Actor(actor.pid, actor.start, actor.exe, actor.argv_sha, tasks)
    return core.Snapshot(original.boot, original.stock_hashes, tuple(actors), original.station,
        fingerprint or original.station_state_sha, original.station_frequency, original.interfaces,
        original.ipv4, original.ipv6_addresses, original.ipv6_routes, original.station_completed)


class JournalTransactionTests(unittest.TestCase):
    def setUp(self):
        # Target adapter tripwires, not global os.stat (unittest may need it).
        for cls in (coordination._LinuxIo, files._LinuxIo, pending._LinuxIo):
            for name in ('validate', 'open_root', 'open_at', 'fstat', 'stat_at', 'close',
                         'read', 'write', 'fsync', 'seek_start', 'flock', 'rename_at'):
                if hasattr(cls, name):
                    patcher = mock.patch.object(cls, name, side_effect=AssertionError('actual OS forbidden'))
                    patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(proc.ProcReader, 'read_self', side_effect=AssertionError('actual proc forbidden'))
        patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket'):
            patcher = mock.patch(target, side_effect=AssertionError('actual native/network forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)

    def make(self, io=None, reader=None, **kwargs):
        io, reader = io or CombinedIo(), reader or Reader()
        reader.boot = baseline().boot
        owner = transaction.ClientJournalTransaction(TOKEN, IDENTITY,
            _coordination_io=io, _files_io=io, _pending_io=io, _proc_reader=reader,
            _clock=io.clock, **kwargs)
        self.addCleanup(owner.close)
        return owner, io, reader

    def opened(self, **kwargs):
        owner, io, reader = self.make(**kwargs)
        session = owner.open()
        return owner, io, reader, session

    def prepared(self, **kwargs):
        owner, io, reader, session = self.opened(**kwargs)
        receipt = owner.prepare_initial(session, baseline(), 10.0)
        return owner, io, reader, session, receipt

    def reject(self, action, code=None):
        with self.assertRaises(transaction.JournalTransactionError) as caught: action()
        if code is not None: self.assertEqual(code, caught.exception.code)
        self.assertIn(caught.exception.code, transaction._CODES)
        for value in (TOKEN, '/tmp', 'wlan0', '11111111', 'private'):
            self.assertNotIn(value, str(caught.exception))

    def assert_once_closed(self, io):
        self.assertFalse(io.handles)
        self.assertEqual(len(io.closed), len(set(io.closed)))
        self.assertEqual(set(fd for _, _, _, fd in io.opened), set(io.closed))

    def test_constructor_pure_and_python35_no_rf_or_finish(self):
        owner, io, reader = self.make()
        self.assertFalse(io.opened); self.assertEqual(0, reader.calls)
        self.assertNotIsInstance(owner, core.ClientInitStore)
        for attr in ('finish', 'clear', 'start', 'recover', 'register_inherited', 'provider'):
            self.assertFalse(hasattr(owner, attr))
        with open(transaction.__file__, encoding='utf-8') as source:
            tree = ast.parse(source.read(), feature_version=(3, 5))
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        self.assertFalse({'unlink', 'mkdir', 'kill', 'fork', 'dup', 'socket', 'clear'} &
            {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)})
        self.assertFalse(any(isinstance(node, ast.Import) and any(n.name in ('json', 'fcntl', 'resource')
            for n in node.names) for node in ast.walk(tree)))

    def test_invalid_constructor_no_io(self):
        for kwargs in ({'run_token': '../'}, {'run_token': True}, {'identity': object()},
                {'timeout': True}, {'timeout': 10 ** 1000}, {'timeout': float('nan')},
                {'timeout': float('inf')}, {'_clock': 1}):
            options = {'run_token': TOKEN, 'identity': IDENTITY}; options.update(kwargs)
            self.reject(lambda: transaction.ClientJournalTransaction(**options), 'invalid_config')

    def test_open_actual_two_locks_and_empty_current_same_serialization(self):
        owner, io, reader, session = self.opened()
        self.assertIsNone(owner.current(session))
        self.assertIs(owner._mutex, owner._coordination._serialization_lock)
        self.assertIs(owner._mutex, owner._files._serialization_lock)
        self.assertEqual({'/tmp/' + coordination.DEVICE_LOCK, RUN + '/' + coordination.JOURNAL_LOCK},
            {io.handles[fd][0].path for fd, flags in io.flocks})
        self.assertTrue(all(flags == 6 for fd, flags in io.flocks))
        self.assertEqual(0, reader.calls)
        self.assertNotIn(TARGET, io.nodes); self.assertNotIn(PENDING, io.nodes)
        self.reject(owner.open, 'already_attempted')

    def test_old_global_pending_blocks_no_journal_or_marker_write(self):
        for mode in (stat.S_IFREG | 0o600, stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o700):
            owner, io, _ = self.make()
            existing = io.add(PENDING, mode, b'old-or-unknown')
            self.reject(owner.open)
            self.assertIs(existing, io.nodes[PENDING]); self.assertEqual(b'old-or-unknown', existing.data)
            self.assertNotIn(TARGET, io.nodes)
            self.assertFalse(any(op in ('write', 'rename') for op, path in io.ops))
            self.assert_once_closed(io)

    def test_preexisting_journal_is_not_adopted(self):
        owner, io, _ = self.make()
        old = io.add(TARGET, data=codec.encode_journal(core.Journal(IDENTITY, 'prepared', baseline(), 10)))
        self.reject(owner.open, 'current_exists')
        self.assertIs(old, io.nodes[TARGET]); self.assertNotIn(PENDING, io.nodes)
        self.assert_once_closed(io)

    def test_exact_session_and_once_prepare(self):
        owner, io, _, session, receipt = self.prepared()
        copied = transaction.TransactionSession(owner._issuer)
        before = list(io.ops)
        self.reject(lambda: owner.current(copied), 'invalid_session')
        self.reject(lambda: owner.close(copied), 'invalid_session')
        self.assertEqual(before, io.ops)
        self.reject(lambda: owner.prepare_initial(session, baseline(), 10), 'prepare_already_attempted')
        self.assertIs(owner._receipt, receipt)

    def test_prepare_actual_publish_then_marker_fsync_binding_readback(self):
        owner, io, reader, session, receipt = self.prepared()
        self.assertIs(type(receipt), transaction.TransactionReceipt)
        self.assertEqual(codec.encode_journal(receipt.journal), io.nodes[TARGET].data)
        self.assertEqual('prepared', receipt.journal.stage)
        self.assertEqual('retained_observed', owner._marker_observation.marker_state)
        self.assertIs(owner._binding, owner._files._owned_marker_binding)
        self.assertIs(owner._binding, owner._coordination._owned_marker_binding)
        self.assertIs(owner._mutex, owner._marker._serialization_lock)
        self.assertIs(owner._epoch, owner._files._owned_marker_epoch)
        self.assertTrue(owner.status()['marker_bound'])
        self.assertGreater(reader.calls, 2)
        rename = next(i for i, (op, path) in enumerate(io.ops) if op == 'rename')
        creation = next(i for i, (op, path) in enumerate(io.ops) if op == 'open' and path == PENDING)
        self.assertLess(rename, creation)
        self.assertIn(('fsync', PENDING), io.ops)
        self.assertEqual(receipt.canonical.data, owner.current(session).data)

    def test_generation_commit_allows_inode_change_not_marker_change(self):
        owner, io, _, session, first = self.prepared()
        marker = io.nodes[PENDING]
        previous = first.canonical.metadata[1]
        second = owner.commit(session, first, core.Journal(IDENTITY, 'prepared', baseline(), 9))
        third = owner.commit(session, second, core.Journal(IDENTITY, 'prepared', baseline(), 9))
        self.assertEqual(3, third.canonical._generation)
        self.assertNotEqual(previous, second.canonical.metadata[1])
        self.assertIs(marker, io.nodes[PENDING]); self.assertEqual(3, owner._files._generation)
        self.assertEqual(third.canonical.metadata, owner.current(session).metadata)

    def test_forged_and_stale_receipts_rejected_before_io(self):
        owner, io, _, session, first = self.prepared()
        forged = transaction.TransactionReceipt(first.canonical, owner._issuer, session, owner._epoch)
        before = list(io.ops)
        self.reject(lambda: owner.commit(session, forged, first.journal), 'invalid_receipt')
        self.assertEqual(before, io.ops)
        owner.commit(session, first, first.journal)
        before = list(io.ops)
        self.reject(lambda: owner.commit(session, first, first.journal), 'invalid_receipt')
        self.assertEqual(before, io.ops)

    def test_no_stage_escalation_or_ready_owned_actors(self):
        owner, io, _, session, first = self.prepared()
        for stage in ('new', 'reconciled', 'cleanup_verified', 'cleanup_intent'):
            record = core.Journal(IDENTITY, stage, baseline(), 9)
            before = list(io.ops)
            self.reject(lambda: owner.commit(session, first, record), 'invalid_record')
            self.assertEqual(before, io.ops)
        from test_client_journal_codec import record as rf_record
        self.reject(lambda: owner.commit(session, first, rf_record()), 'invalid_record')

    def test_complete_baseline_task_states_not_only_key_checked(self):
        owner, io, _, session, first = self.prepared()
        changed = changed_baseline(state='S')
        self.assertEqual(baseline().key(), changed.key())
        before = list(io.ops)
        self.reject(lambda: owner.commit(session, first,
            core.Journal(IDENTITY, 'prepared', changed, 9)), 'baseline_changed')
        self.assertEqual(before, io.ops)

    def test_changed_identity_baseline_and_deadline_cannot_rebase(self):
        owner, io, _, session, first = self.prepared()
        for record, code in ((core.Journal(core.Identity('b' * 64), 'prepared', baseline(), 9), 'invalid_record'),
                (core.Journal(IDENTITY, 'prepared', changed_baseline(fingerprint='e' * 64), 9), 'baseline_changed'),
                (core.Journal(IDENTITY, 'prepared', baseline(), 11), 'deadline_extended')):
            before = list(io.ops)
            self.reject(lambda: owner.commit(session, first, record), code)
            self.assertEqual(before, io.ops)

    def test_invalid_baseline_deadline_and_commit_before_prepare(self):
        owner, io, _, session = self.opened()
        self.reject(lambda: owner.prepare_initial(session, object(), 10), 'invalid_baseline')
        for deadline in (True, float('nan'), float('inf'), 10 ** 1000):
            self.reject(lambda: owner.prepare_initial(session, baseline(), deadline), 'invalid_deadline')
        self.reject(lambda: owner.commit(session, None, core.Journal(IDENTITY, 'prepared', baseline(), 10)), 'not_prepared')
        self.assertNotIn(TARGET, io.nodes); self.assertNotIn(PENDING, io.nodes)

    def test_marker_identical_bytes_foreign_inode_seals_without_overwrite(self):
        owner, io, _, session, first = self.prepared()
        replacement = io.add(PENDING, data=io.nodes[PENDING].data); replacement.ino += 1000
        before = sum(op == 'rename' for op, path in io.ops)
        self.reject(lambda: owner.commit(session, first, first.journal))
        self.assertEqual(before, sum(op == 'rename' for op, path in io.ops))
        self.assertIs(replacement, io.nodes[PENDING]); self.assertFalse(owner.status()['opened'])
        self.assert_once_closed(io)

    def test_marker_owner_change_seals_before_next_publication(self):
        owner, io, reader, session, first = self.prepared()
        reader.actor = core.Actor(123, 301, '/usr/bin/python3', 'b' * 64, ((123, 301, 'S'),))
        before = sum(op == 'rename' for op, path in io.ops)
        self.reject(lambda: owner.commit(session, first, first.journal))
        self.assertEqual(before, sum(op == 'rename' for op, path in io.ops))
        self.assertIn(PENDING, io.nodes); self.assert_once_closed(io)

    def test_journal_foreign_inode_or_bytes_cannot_rebase(self):
        for substituted in (True, False):
            owner, io, _, session, first = self.prepared()
            if substituted:
                node = io.add(TARGET, data=io.nodes[TARGET].data); node.ino += 1000
            else:
                io.nodes[TARGET].data = codec.encode_journal(core.Journal(IDENTITY, 'prepared', baseline(), 8))
                io.nodes[TARGET].stamp += 1
            self.reject(lambda: owner.current(session), 'readback_changed')
            self.assertIn(PENDING, io.nodes); self.assert_once_closed(io)

    def test_journal_fsync_unknown_retains_original_no_marker_or_retry(self):
        owner, io, _, session = self.opened()
        io.faults[('fsync', RUN)] = OSError(errno.EIO, 'HOST injected')
        self.reject(lambda: owner.prepare_initial(session, baseline(), 10))
        self.assertIn(TARGET, io.nodes); self.assertNotIn(PENDING, io.nodes)
        status = owner.status()
        self.assertTrue(status['checkpoint_unverified']); self.assertTrue(status['published_unknown'])
        self.assertTrue(status['write_pending']); self.assert_once_closed(io)
        self.reject(lambda: owner.prepare_initial(session, baseline(), 10), 'not_open')

    def test_successful_canonical_retained_before_failing_postcheck(self):
        owner, io, _, session = self.opened()
        original = owner._files.commit
        def committed(*args):
            value = original(*args)
            io.faults[('flock', '/tmp/' + coordination.DEVICE_LOCK)] = OSError(errno.EIO, 'HOST injected')
            return value
        with mock.patch.object(owner._files, 'commit', side_effect=committed):
            self.reject(lambda: owner.prepare_initial(session, baseline(), 10))
        self.assertIs(type(owner._candidate), files.CanonicalRecord)
        self.assertIs(owner._candidate, owner._canonical)
        self.assertIn(TARGET, io.nodes); self.assertNotIn(PENDING, io.nodes)
        self.assertTrue(owner.status()['checkpoint_unverified'])
        self.assert_once_closed(io)

    def test_pending_fsync_unknown_keeps_journal_partial_marker_and_refs(self):
        owner, io, _, session = self.opened()
        io.faults[('fsync', '/tmp')] = OSError(errno.EIO, 'HOST injected')
        self.reject(lambda: owner.prepare_initial(session, baseline(), 10))
        self.assertIn(TARGET, io.nodes); self.assertIn(PENDING, io.nodes)
        self.assertIsNotNone(owner._marker._ticket)
        self.assertTrue(owner.status()['marker_unverified'])
        self.assertFalse(owner.close().complete()); self.assert_once_closed(io)

    def test_actual_create_observation_retained_before_bind_failure(self):
        owner, io, _, session = self.opened()
        with mock.patch.object(pending.ClientPendingMarker, 'bind_files', side_effect=RuntimeError('HOST injected')):
            self.reject(lambda: owner.prepare_initial(session, baseline(), 10))
        self.assertIs(type(owner._marker_observation), pending.PendingObservation)
        self.assertTrue(owner._marker_observation.durable_created)
        self.assertIn(PENDING, io.nodes); self.assertIsNone(owner._binding)
        self.assertTrue(owner.status()['marker_unverified']); self.assert_once_closed(io)

    def test_binding_reference_retained_before_postcheck_failure(self):
        owner, io, _, session = self.opened()
        original = pending.ClientPendingMarker.bind_files
        def bound(marker, *args):
            value = original(marker, *args)
            io.faults[('flock', '/tmp/' + coordination.DEVICE_LOCK)] = OSError(errno.EIO, 'HOST injected')
            return value
        with mock.patch.object(pending.ClientPendingMarker, 'bind_files', bound):
            self.reject(lambda: owner.prepare_initial(session, baseline(), 10))
        self.assertIs(type(owner._binding), pending.OwnedMarkerBinding)
        self.assertIn(PENDING, io.nodes); self.assertTrue(owner.status()['marker_unverified'])
        self.assert_once_closed(io)

    def test_malformed_binding_result_not_true_authorization(self):
        owner, io, _, session = self.opened()
        with mock.patch.object(pending.ClientPendingMarker, 'bind_files', return_value=True):
            self.reject(lambda: owner.prepare_initial(session, baseline(), 10), 'marker_unverified')
        self.assertIs(owner._binding, True)
        self.assertFalse(owner.status()['marker_bound']); self.assertIn(PENDING, io.nodes)
        self.assert_once_closed(io)

    def test_malformed_commit_result_retained_no_marker_success(self):
        owner, io, _, session = self.opened()
        returned = object()
        with mock.patch.object(owner._files, 'commit', return_value=returned):
            self.reject(lambda: owner.prepare_initial(session, baseline(), 10), 'readback_changed')
        self.assertIs(returned, owner._candidate); self.assertNotIn(PENDING, io.nodes)
        self.assertTrue(owner.status()['checkpoint_unverified']); self.assert_once_closed(io)

    def test_unknown_open_keeps_exact_ticket_no_numeric_close_guess(self):
        owner, io, _ = self.make()
        io.unknown_open = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): owner.open()
        ticket = owner._coordination._inventory[0]
        self.assertIs(ticket.io, io); self.assertTrue(ticket.opening_unknown)
        self.assertFalse(ticket.attempted); self.assertFalse(io.closed)
        self.assertTrue(owner.status()['resource_pending'])
        self.assertFalse(owner.close().complete())

    def test_marker_unknown_open_keeps_component_no_guess_or_reopen(self):
        owner, io, _, session = self.opened()
        def unknown(obj, action, path, count):
            if action == 'open' and path == PENDING: raise KeyboardInterrupt()
        io.hook = unknown
        with self.assertRaises(KeyboardInterrupt): owner.prepare_initial(session, baseline(), 10)
        self.assertTrue(owner._marker._ticket.opening_unknown)
        self.assertIs(owner._marker._ticket.io, io)
        self.assertFalse(owner._marker._ticket.attempted)
        self.assertTrue(owner.status()['resource_pending'])
        self.assertEqual(1, io.counts[('open', PENDING)])
        self.assertFalse(owner.close().complete())

    def test_close_exact_independent_once_and_retains_marker_not_restore(self):
        owner, io, _, session, first = self.prepared()
        marker, journal = io.nodes[PENDING], io.nodes[TARGET]
        observed = owner.close(session)
        self.assertTrue(observed.complete()); self.assertIs(type(observed), transaction.JournalTransactionCloseObservation)
        self.assert_once_closed(io); before = list(io.closed)
        self.assertTrue(owner.close(session).complete()); self.assertEqual(before, io.closed)
        self.assertIs(marker, io.nodes[PENDING]); self.assertIs(journal, io.nodes[TARGET])
        self.assertFalse(owner.status()['restore_verified']); self.assertFalse(owner.status()['finish_implemented'])
        self.reject(lambda: owner.current(session), 'not_open')

    def test_marker_close_error_sticky_other_components_still_close(self):
        owner, io, _, session, _ = self.prepared()
        fd = owner._marker._ticket.fd
        io.close_fail[fd] = OSError(errno.EINTR, 'HOST injected')
        observed = owner.close(session)
        self.assertFalse(observed.complete()); self.assertFalse(observed.marker_closed)
        self.assertTrue(observed.files_closed); self.assertTrue(observed.coordination_closed)
        self.assertEqual(1, io.closed.count(fd))
        io.handles.pop(fd)
        observed = owner.close(session)
        self.assertFalse(observed.complete()); self.assertTrue(observed.resource_pending)
        self.assertEqual(1, io.closed.count(fd)); self.assertIn(PENDING, io.nodes)

    def test_component_close_baseexception_does_not_skip_following_close(self):
        owner, io, _, session, _ = self.prepared()
        original = owner._marker.close
        def interrupted(): original(); raise KeyboardInterrupt()
        with mock.patch.object(owner._marker, 'close', side_effect=interrupted):
            observed = owner.close(session)
        self.assertTrue(observed.files_closed); self.assertTrue(observed.coordination_closed)
        self.assertTrue(observed.resource_pending); self.assertFalse(observed.complete())
        self.assert_once_closed(io)

    def test_late_ebadf_never_clears_unknown_close(self):
        owner, io, _, session = self.opened()
        fd = owner._files._inventory[0].fd
        io.close_fail[fd] = OSError(errno.EINTR, 'HOST injected')
        self.assertFalse(owner.close(session).complete())
        io.handles.pop(fd)
        observed = owner.close(session)
        self.assertTrue(observed.resource_pending); self.assertFalse(observed.files_closed)
        self.assertEqual(1, io.closed.count(fd))

    def test_deadline_expiry_after_commit_keeps_checkpoint_unknown_closes_all(self):
        owner, io, _, session = self.opened()
        original = owner._files.commit
        def delayed(*args):
            value = original(*args); io.clock.value = 10.0; return value
        with mock.patch.object(owner._files, 'commit', side_effect=delayed):
            self.reject(lambda: owner.prepare_initial(session, baseline(), 10), 'expired')
        self.assertIs(type(owner._candidate), files.CanonicalRecord)
        self.assertTrue(owner.status()['checkpoint_unverified']); self.assertNotIn(PENDING, io.nodes)
        self.assert_once_closed(io)

    def test_regressed_or_invalid_clock_closes_before_audit(self):
        for value in (0.5, True, float('nan'), float('inf')):
            owner, io, _, session = self.opened()
            io.clock.value = value
            self.reject(lambda: owner.current(session))
            self.assert_once_closed(io)
            self.assertTrue(owner.status()['resource_pending'])

    def test_status_fixed_private_reprs_and_no_admission(self):
        owner, io, _, session, receipt = self.prepared()
        status = owner.status()
        for key in ('marker_clear_implemented', 'finish_implemented', 'baseline_authenticated',
                'manifest_authenticated', 'executor_verified', 'same_ofd_verified', 'restore_verified',
                'rf_admission', 'full_store_implemented', 'receive_available', 'send_available'):
            self.assertIs(status[key], False)
        for value in (session, receipt, receipt.canonical, owner.close(session)):
            for secret in (TOKEN, 'wlan0', '/tmp', 'a' * 64): self.assertNotIn(secret, repr(value))
            with self.assertRaises(AttributeError): value.new_flag = True
        self.assertNotIn(TOKEN, repr(status)); self.assertNotIn('/tmp', repr(status))


if __name__ == '__main__':
    unittest.main()
