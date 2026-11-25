"""HOST actual three file/lock components, FakeIO/synthetic records ONLY."""
import ast
import errno
import os
import stat
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime')))
import mta_client_store as s
import mta_client_coordination as c
import mta_client_files as f
import mta_client_pending as p
import mta_client_proc as proc
import mta_client_journal_codec as codec
import mta_p2p_client_init as core
from test_client_journal_transaction import CombinedIo, changed_baseline
from test_client_files import TOKEN, RUN, TARGET, PENDING
from test_client_pending import Reader
from test_client_journal_codec import baseline, record, IDENTITY


class StoreIo(CombinedIo):
    def unlink_at(self, parent, name):
        path = self.path(parent, name)
        self.event('unlink', path)
        if path not in self.nodes: raise OSError(errno.ENOENT, 'HOST absent')
        node = self.nodes.pop(path)
        node.links = 0
        return (0, 0)


class RestoreReader(object):
    """Explicitly synthetic trusted producer with exact issuance registry."""
    def __init__(self):
        self.issued, self.calls = [], []
        self.mode, self.hook = 'fresh', None

    def read_restore(self, store, locks, request, deadline):
        self.calls.append((store, locks, request, deadline, store._finish_phase))
        if self.hook: self.hook(self, store, locks, request, len(self.calls))
        if self.mode == 'error': raise OSError(errno.EIO, 'private')
        if self.mode == 'reuse' and self.issued: return self.issued[-1][3]
        if self.mode == 'bool': value = True
        elif self.mode == 'changed': value = (changed_baseline(state='S'), core.CloseProof(2, (True, True), (True, True)))
        elif self.mode == 'unclosed': value = (baseline(), core.CloseProof(2, (True, True), (True, False)))
        else: value = (baseline(), core.CloseProof(2, (True, True), (True, True)))
        self.issued.append((store, locks, request, value))
        return value

    def authenticate_restore(self, store, locks, request, value, deadline):
        if self.mode == 'auth_bool': return True
        if self.mode == 'auth_error': raise ValueError('private')
        if not any(a is store and b is locks and d is request and v is value for a, b, d, v in self.issued):
            raise ValueError('private not issued')
        return None


class PriorReader(object):
    def __init__(self): self.issued = []

    def read_prior(self, store, locks, original, deadline):
        value = baseline(); self.issued.append((store, locks, original, value)); return value

    def authenticate_prior(self, store, locks, original, value, deadline):
        if not any(a is store and b is locks and d is original and v is value for a, b, d, v in self.issued):
            raise ValueError('private')
        return None


class DurableStoreTests(unittest.TestCase):
    def setUp(self):
        for cls in (c._LinuxIo, f._LinuxIo, p._LinuxIo):
            for name in ('validate', 'open_root', 'open_at', 'fstat', 'stat_at', 'close',
                         'read', 'write', 'fsync', 'seek_start', 'flock', 'rename_at', 'unlink_at'):
                if hasattr(cls, name):
                    patcher = mock.patch.object(cls, name, side_effect=AssertionError('actual OS forbidden'))
                    patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket'):
            patcher = mock.patch(target, side_effect=AssertionError('actual OS forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(proc.ProcReader, 'read_self', side_effect=AssertionError('actual proc forbidden'))
        patcher.start(); self.addCleanup(patcher.stop)

    def make(self, io=None, restore=None, prior=None, **kwargs):
        io, reader = io or StoreIo(), Reader(); reader.boot = baseline().boot
        obj = s.DurableClientInitStore(TOKEN, IDENTITY, _coordination_io=io,
            _files_io=io, _pending_io=io, _proc_reader=reader, _clock=io.clock,
            _restore_reader=restore, _prior_reader=prior, **kwargs)
        self.addCleanup(obj.close)
        return obj, io, reader

    def acquired(self, **kwargs):
        obj, io, reader = self.make(**kwargs)
        locks = obj.acquire(IDENTITY, 3.0)
        return obj, io, reader, locks

    def prepared(self, **kwargs):
        obj, io, reader, locks = self.acquired(**kwargs)
        journal = obj.commit(locks, core.Journal(IDENTITY, 'prepared', baseline(), 10.0))
        return obj, io, reader, locks, journal

    def cleaned(self, restore=None):
        values = self.prepared(restore=restore)
        obj, io, reader, locks, journal = values
        journal = obj.commit(locks, journal.replace(stage='cleanup_intent'))
        journal = obj.commit(locks, journal.replace(stage='cleanup_verified'))
        return obj, io, reader, locks, journal

    def reject(self, action, code=None):
        with self.assertRaises(s.DurableStoreError) as caught: action()
        if code is not None: self.assertEqual(code, caught.exception.code)
        self.assertIn(caught.exception.code, s._DURABLE_CODES)
        for private in (TOKEN, RUN, '/usr/bin/', 'wlan0', 'private'):
            self.assertNotIn(private, str(caught.exception))

    def test_constructor_pure_default_missing_producers_and_python35(self):
        obj, io, reader = self.make()
        self.assertEqual([], io.ops); self.assertEqual(0, reader.calls)
        self.assertIsInstance(obj, core.ClientInitStore)
        self.assertIsNone(obj._restore_reader); self.assertIsNone(obj._prior_reader)
        for module in (s, c):
            with open(module.__file__, encoding='utf-8') as source:
                tree = ast.parse(source.read(), feature_version=(3, 5))
            self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))
            self.assertFalse({'mkdir', 'unlink', 'fork', 'dup', 'kill', 'waitpid', 'socket'} &
                {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)})
        self.assertFalse(obj.status()['send_available']); self.assertFalse(obj.status()['receive_available'])

    def test_invalid_config_finite_types_no_io(self):
        for kwargs in ({'run_token': True}, {'run_token': '../'}, {'timeout': True},
                {'timeout': 10 ** 1000}, {'timeout': float('nan')}, {'identity': object()},
                {'_restore_reader': True}, {'_prior_reader': lambda: True}):
            options = dict(run_token=TOKEN, identity=IDENTITY); options.update(kwargs)
            self.reject(lambda: s.DurableClientInitStore(**options), 'invalid_config')

    def test_acquire_real_components_same_domain_and_once(self):
        obj, io, _, locks = self.acquired()
        self.assertIs(obj._mutex, obj._coordination._serialization_lock)
        self.assertIs(obj._mutex, obj._files._serialization_lock)
        self.assertIsNone(obj.current(locks)); self.assertTrue(obj.pending_clear(locks))
        self.assertEqual(6, len(obj._coordination._inventory)); self.assertEqual(4, len(obj._files._anchors))
        self.assertTrue(all(flags == 6 for _, flags in io.flocks))
        before = list(io.ops)
        self.reject(lambda: obj.acquire(IDENTITY, 3), 'already_attempted')
        self.assertEqual(before, io.ops)

    def test_old_pending_never_adopted_or_unlinked(self):
        for mode in (stat.S_IFREG | 0o600, stat.S_IFDIR | 0o700, stat.S_IFLNK | 0o777):
            io = StoreIo(); original = io.add(PENDING, mode, b'unknown')
            obj, _, _ = self.make(io)
            self.reject(lambda: obj.acquire(IDENTITY, 3.0))
            self.assertIs(original, io.nodes[PENDING]); self.assertNotIn(TARGET, io.nodes)
            self.assertFalse(any(op == 'unlink' for op, _ in io.ops))
            self.assertFalse(io.handles)

    def test_existing_same_identity_journal_never_adopted(self):
        io = StoreIo(); original = io.add(TARGET, data=codec.encode_journal(core.Journal(IDENTITY, 'prepared', baseline(), 10)))
        obj, _, _ = self.make(io)
        self.reject(lambda: obj.acquire(IDENTITY, 3.0), 'current_exists')
        self.assertIs(original, io.nodes[TARGET]); self.assertNotIn(PENDING, io.nodes)
        self.assertFalse(io.handles)

    def test_default_prior_false_and_typed_private_prior_registry(self):
        obj, _, _, locks = self.acquired()
        self.assertFalse(obj.prior_clear(locks, baseline(), 3.0))
        reader = PriorReader(); obj2, _, _, locks2 = self.acquired(prior=reader)
        self.assertTrue(obj2.prior_clear(locks2, baseline(), 3.0)); self.assertEqual(1, len(reader.issued))
        reader.authenticate_prior = lambda *args: True
        self.reject(lambda: obj2.prior_clear(locks2, baseline(), 3.0), 'producer_unknown')

    def test_first_prepared_actual_journal_then_marker_binding(self):
        obj, io, _, locks, journal = self.prepared()
        self.assertEqual(codec.encode_journal(journal), io.nodes[TARGET].data)
        self.assertTrue(obj.pending_matches(locks, journal)); self.assertFalse(obj.pending_clear(locks))
        self.assertIs(obj._marker._coordination, obj._coordination)
        self.assertIs(obj._marker._serialization_lock, obj._mutex)
        self.assertIs(obj._binding, obj._marker._binding_ticket.binding)
        rename_index = io.ops.index(('rename', RUN + '/journal.00000001.tmp'))
        pending_index = io.ops.index(('open', PENDING))
        self.assertLess(rename_index, pending_index)
        self.assertIn(('fsync', '/tmp'), io.ops)

    def test_forged_lockset_and_foreign_identity_zero_io(self):
        obj, io, _, locks = self.acquired()
        before = list(io.ops)
        copied = c.LockSet(obj._coordination._issuer, locks._device, locks._journal)
        self.reject(lambda: obj.current(copied), 'invalid_locks')
        self.reject(lambda: obj.acquire(core.Identity('b' * 64), 3), 'invalid_identity')
        self.assertEqual(before, io.ops)

    def test_complete_full_trace_handoff_over_ttl_terminal_and_fd_budget(self):
        producer = RestoreReader()
        obj, io, _, locks, journal = self.prepared(restore=producer)
        template = record()
        changes = (
            dict(stage='watchdog_intent', watchdog_ticket=template.watchdog_ticket),
            dict(stage='watchdog_saved', watchdog=template.watchdog),
            dict(stage='interface_intent', interface_ticket=template.interface_ticket),
            dict(stage='interface_owned', owned=template.owned),
            dict(stage='controller_intent', controller_ticket=template.controller_ticket),
            dict(stage='controller_saved', controller=template.controller),
            dict(stage='client_init_ready', ready=True))
        for fields in changes:
            self.assertTrue(obj.lock_valid(locks))
            self.assertTrue(core._same_journal(obj.current(locks), journal))
            self.assertTrue(obj.pending_matches(locks, journal))
            journal = obj.commit(locks, journal.replace(**fields))
            self.assertTrue(obj.pending_matches(locks, journal))
        original_device = locks._device
        proof = obj.active_return(locks, journal)
        self.assertEqual(1, proof.expected); self.assertTrue(proof.complete())
        self.reject(lambda: obj.current(locks), 'invalid_locks')
        self.assertFalse(obj._unknown)
        io.clock.value = 12.0  # RF deadline remains 10; actual cleanup I/O has its own budget.
        new = obj.acquire(IDENTITY, 15.0, inherited=locks)
        self.assertIs(new._device, original_device); self.assertIsNot(new, locks)
        self.assertEqual(7, len(obj._coordination._inventory))
        self.assertEqual(10, obj.current(new).deadline)
        journal = obj.commit(new, journal.replace(stage='cleanup_intent', ready=False))
        journal = obj.commit(new, journal.replace(stage='cleanup_verified'))
        receipt = obj.finish(new, journal, True, 15.0)
        self.assertTrue(receipt.complete); self.assertEqual('reconciled', receipt.record.stage)
        self.assertEqual(10, receipt.record.deadline)
        self.assertTrue(obj.authenticate_finish(new, journal, receipt, 15.0))
        self.assertEqual(original_device.fd, io.closed[-1]); self.assertFalse(io.handles)
        self.assertEqual(3, len(producer.calls))
        self.assertLess(len(obj._files._inventory), f.MAX_RESOURCES)
        print('HOST_FULL_TRACE_FILES_HISTORY=%d COORD_HISTORY=%d' %
              (len(obj._files._inventory), len(obj._coordination._inventory)))

    def test_reacquire_read_current_only_after_new_journal_flock(self):
        obj, io, _, locks, journal = self.prepared()
        obj.active_return(locks, journal); io.ops[:] = []
        new = obj.acquire(IDENTITY, 3.0, inherited=locks)
        self.assertLess(io.ops.index(('flock', RUN + '/journal.lock')), io.ops.index(('open', TARGET)))
        self.assertIs(new._device, locks._device)
        self.reject(lambda: obj.acquire(IDENTITY, 3, inherited=new), 'already_attempted')

    def test_suspended_reads_do_not_revoke_valid_same_instance_recovery(self):
        obj, _, _, locks, journal = self.prepared()
        obj.active_return(locks, journal)
        for action in (lambda: obj.lock_valid(locks), lambda: obj.pending_clear(locks),
                       lambda: obj.pending_matches(locks, journal)):
            self.reject(action, 'invalid_locks')
        self.assertFalse(obj._unknown)
        self.assertIs(type(obj.acquire(IDENTITY, 3, inherited=locks)), c.LockSet)

    def test_foreign_recovery_or_external_store_never_reopens_device(self):
        obj, io, _, locks, journal = self.prepared()
        obj.active_return(locks, journal)
        before = list(io.opened)
        self.reject(lambda: obj.acquire(IDENTITY, 3, inherited=c.LockSet(obj._coordination._issuer, locks._device, locks._journal)))
        self.assertEqual(before, io.opened)
        other, io2, _ = self.make()
        self.reject(lambda: other.acquire(IDENTITY, 3, inherited=locks), 'invalid_locks')
        self.assertFalse(io2.opened)

    def test_record_cannot_extend_rf_deadline_or_mutate_full_baseline(self):
        for changed in ('ttl', 'tasks', 'identity'):
            obj, io, _, locks, journal = self.prepared()
            value = journal.replace(stage='cleanup_intent', deadline=11 if changed == 'ttl' else 10,
                baseline=changed_baseline(state='S') if changed == 'tasks' else journal.baseline,
                identity=core.Identity('b' * 64) if changed == 'identity' else IDENTITY)
            before = list(io.ops)
            self.reject(lambda: obj.commit(locks, value))
            self.assertEqual(before, io.ops)

    def test_skip_stage_or_ready_terminal_forgery_no_write(self):
        obj, io, _, locks, journal = self.prepared()
        before = list(io.ops)
        for stage in ('cleanup_verified', 'reconciled'):
            self.reject(lambda: obj.commit(locks, journal.replace(stage=stage)), 'invalid_transition')
        self.assertEqual(before, io.ops)

    def test_cleanup_record_persisted_after_rf_ttl_without_extension(self):
        obj, io, _, locks, journal = self.prepared()
        io.clock.value = 12
        result = obj.commit(locks, journal.replace(stage='cleanup_intent'))
        self.assertEqual(10, result.deadline); self.assertEqual('cleanup_intent', result.stage)
        self.assertEqual(codec.encode_journal(result), io.nodes[TARGET].data)

    def test_changed_current_inode_or_full_bytes_never_rebased(self):
        for changed in ('inode', 'bytes'):
            obj, io, _, locks, journal = self.prepared()
            canonical = obj._canonical
            if changed == 'inode': io.nodes[TARGET].ino += 1
            else: io.nodes[TARGET].data += b' '
            self.reject(lambda: obj.current(locks))
            self.assertIs(obj._canonical, canonical); self.assertTrue(obj._unknown)
            self.assertTrue(obj._observations)

    def test_publication_return_saved_before_postcheck_unknown(self):
        obj, io, _, locks, journal = self.prepared()
        original = obj._files.commit
        returned = []
        def publish(expected, value):
            result = original(expected, value); returned.append(result)
            io.nodes[PENDING].ino += 1
            return result
        obj._files.commit = publish
        self.reject(lambda: obj.commit(locks, journal.replace(stage='cleanup_intent')))
        self.assertIs(obj._candidate, returned[0]); self.assertIs(obj._canonical, returned[0])
        self.assertIn(PENDING, io.nodes)

    def test_unknown_open_keeps_creator_and_blocks_complete(self):
        obj, io, _, locks, journal = self.prepared()
        io.unknown_open = MemoryError('private')
        self.reject(lambda: obj.current(locks))
        unknown = obj._files._inventory[-1]
        self.assertTrue(unknown.opening_unknown); self.assertIs(unknown.io, io)
        io.unknown_open = None
        result = obj.finish(locks, journal, False, 3)
        self.assertFalse(result.complete); self.assertTrue(result.resource_pending)
        self.assertIs(unknown, obj._files._inventory[-1])

    def test_missing_restore_reader_normal_true_retains_marker_not_completion(self):
        obj, io, _, locks, journal = self.cleaned()
        result = obj.finish(locks, journal, True, 3)
        self.assertFalse(result.complete); self.assertFalse(result.terminal_durable)
        self.assertEqual('retained_observed', result.marker_state)
        self.assertEqual('not_attempted', result.clear_durability)
        self.assertIn(PENDING, io.nodes); self.assertFalse(any(op == 'unlink' for op, _ in io.ops))
        self.assertTrue(result.resources_closed)
        self.assertTrue(obj.authenticate_finish(locks, journal, result, 3))

    def test_typed_and_fresh_restore_not_bool_or_reused_cache(self):
        for mode in ('bool', 'changed', 'unclosed', 'reuse', 'auth_bool', 'auth_error', 'error'):
            producer = RestoreReader(); producer.mode = mode
            obj, io, _, locks, journal = self.cleaned(restore=producer)
            result = obj.finish(locks, journal, True, 3)
            self.assertFalse(result.complete); self.assertIn(PENDING, io.nodes)
            self.assertFalse(any(op == 'unlink' for op, _ in io.ops))
            self.assertTrue(producer.calls)
            if mode == 'error': self.assertEqual([], obj._restore_observations)
            else: self.assertTrue(obj._restore_observations)

    def test_true_finish_actual_terminal_publish_clear_fsync_then_all_close_device_last(self):
        producer = RestoreReader()
        obj, io, _, locks, journal = self.cleaned(restore=producer)
        result = obj.finish(locks, journal, True, 3)
        self.assertTrue(result.complete); self.assertTrue(result.terminal_durable)
        self.assertEqual('absent_observed', result.marker_state); self.assertEqual('verified', result.clear_durability)
        self.assertNotIn(PENDING, io.nodes); self.assertFalse(io.handles)
        self.assertEqual(locks._device.fd, io.closed[-1])
        self.assertEqual(len(io.closed), len(set(io.closed)))
        self.assertEqual(1, io.counts[('unlink', PENDING)])
        self.assertEqual(3, len(producer.calls))
        self.assertIs(obj._terminal_canonical, obj._canonical)
        before = list(io.ops), list(io.opened), list(io.closed), list(io.flocks)
        self.assertTrue(obj.authenticate_finish(locks, journal, result, 3))
        self.assertEqual(before, (io.ops, io.opened, io.closed, io.flocks))

    def test_finish_false_does_not_invoke_restoration_or_clear(self):
        producer = RestoreReader()
        obj, io, _, locks, journal = self.prepared(restore=producer)
        result = obj.finish(locks, journal, False, 3)
        self.assertFalse(result.complete); self.assertTrue(result.resources_closed)
        self.assertEqual([], producer.calls); self.assertIn(PENDING, io.nodes)
        self.assertEqual('retained_observed', result.marker_state)
        self.assertTrue(obj.closed_locks(locks, 3).complete())

    def test_no_record_finish_observes_real_absence_without_fake_retained(self):
        obj, io, _, locks = self.acquired()
        result = obj.finish(locks, None, False, 3)
        self.assertEqual('absent_observed', result.marker_state); self.assertFalse(result.complete)
        self.assertTrue(result.resources_closed); self.assertIsNone(result.record)
        self.assertNotIn(PENDING, io.nodes)

    def test_forged_finish_receipt_or_request_not_authenticated_zero_io(self):
        obj, io, _, locks, journal = self.cleaned(restore=RestoreReader())
        actual = obj.finish(locks, journal, True, 3)
        forged = core.FinishReceipt(obj, locks, IDENTITY, journal, actual.record, True,
            True, 'absent_observed', 'verified', True, False, True)
        before = list(io.ops)
        self.assertFalse(obj.authenticate_finish(locks, journal, forged, 3))
        self.assertFalse(obj.authenticate_finish(locks, journal.replace(), actual, 3))
        self.assertEqual(before, io.ops)

    def test_finish_seals_commit_recovery_second_finish_and_close_once(self):
        obj, io, _, locks, journal = self.cleaned(restore=RestoreReader())
        obj.finish(locks, journal, True, 3)
        before = list(io.closed), list(io.opened)
        for action in (lambda: obj.commit(locks, journal), lambda: obj.acquire(IDENTITY, 3, inherited=locks),
                       lambda: obj.finish(locks, journal, True, 3), lambda: obj.current(locks)):
            self.reject(action, 'sealed')
        obj.close(); obj.close()
        self.assertEqual(before, (io.closed, io.opened))

    def test_restore_baseline_change_after_terminal_cas_no_clear(self):
        producer = RestoreReader()
        def changed(reader, store, locks, request, number):
            if number == 2: reader.mode = 'changed'
        producer.hook = changed
        obj, io, _, locks, journal = self.cleaned(restore=producer)
        result = obj.finish(locks, journal, True, 3)
        self.assertTrue(result.terminal_durable); self.assertFalse(result.complete)
        self.assertEqual('reconciled', result.record.stage); self.assertIn(PENDING, io.nodes)
        self.assertFalse(any(op == 'unlink' for op, _ in io.ops))

    def test_restore_change_during_clear_authorization_stops_unlink(self):
        producer = RestoreReader()
        producer.hook = lambda reader, store, locks, request, number: setattr(reader, 'mode', 'changed') if number == 3 else None
        obj, io, _, locks, journal = self.cleaned(restore=producer)
        result = obj.finish(locks, journal, True, 3)
        self.assertFalse(result.complete); self.assertTrue(result.terminal_durable)
        self.assertIn(PENDING, io.nodes); self.assertFalse(any(op == 'unlink' for op, _ in io.ops))

    def test_unlink_fsync_failure_preserves_physical_absence_not_retained(self):
        obj, io, _, locks, journal = self.cleaned(restore=RestoreReader())
        def hook(io, operation, path, count):
            if operation == 'fsync' and path == '/tmp' and PENDING not in io.nodes:
                raise OSError(errno.EIO, 'private')
        io.hook = hook
        result = obj.finish(locks, journal, True, 3)
        self.assertFalse(result.complete); self.assertTrue(result.terminal_durable)
        self.assertEqual('absent_observed', result.marker_state); self.assertEqual('unknown', result.clear_durability)
        self.assertTrue(result.resources_closed); self.assertEqual(1, io.counts[('unlink', PENDING)])

    def test_after_clear_unknown_file_close_separate_marker_and_resources(self):
        obj, io, _, locks, journal = self.cleaned(restore=RestoreReader())
        failed = obj._files._anchors[0][0].fd
        io.close_fail[failed] = OSError(errno.EINTR, 'private')
        result = obj.finish(locks, journal, True, 3)
        self.assertEqual('absent_observed', result.marker_state); self.assertEqual('verified', result.clear_durability)
        self.assertTrue(result.resource_pending); self.assertFalse(result.resources_closed); self.assertFalse(result.complete)
        self.assertEqual(locks._device.fd, io.closed[-1])
        del io.close_fail[failed]; del io.handles[failed]
        before = list(io.closed); obj.close()
        self.assertEqual(before, io.closed)
        self.assertTrue(obj.authenticate_finish(locks, journal, result, 3))

    def test_baseexception_component_close_does_not_skip_device_last(self):
        obj, io, _, locks, journal = self.prepared()
        original = obj._marker.close
        def interrupted(): original(); raise KeyboardInterrupt('private')
        obj._marker.close = interrupted
        result = obj.finish(locks, journal, False, 3)
        self.assertFalse(result.resources_closed); self.assertTrue(result.resource_pending)
        self.assertEqual(locks._device.fd, io.closed[-1]); self.assertFalse(io.handles)

    def test_original_logical_two_slots_not_six_seven_inventory_proof(self):
        obj, _, _, locks, journal = self.prepared()
        obj.active_return(locks, journal)
        proof = obj.closed_locks(locks, 3)
        self.assertEqual(2, proof.expected); self.assertEqual((False, True), proof.closed)
        new = obj.acquire(IDENTITY, 3, inherited=locks)
        proof = obj.closed_locks(locks, 3)
        self.assertEqual((False, False), proof.closed)
        self.assertEqual(7, len(obj._coordination._inventory))
        obj.close()
        self.assertTrue(obj.closed_locks(new, 3).complete())

    def test_expiry_or_invalid_finish_budget_still_independent_all_close(self):
        for deadline in (True, float('nan'), 10 ** 1000, 1.0):
            obj, io, _, locks, journal = self.prepared()
            result = obj.finish(locks, journal, False, deadline)
            self.assertFalse(result.complete); self.assertIn(PENDING, io.nodes)
            self.assertFalse(io.handles); self.assertEqual(locks._device.fd, io.closed[-1])

    def test_every_io_has_shared_domain_and_no_preexec_launch(self):
        obj, io, _, locks, journal = self.cleaned(restore=RestoreReader())
        io.hook = lambda *args: self.assertTrue(obj._mutex._is_owned())
        result = obj.finish(locks, journal, True, 3)
        self.assertTrue(result.complete)
        self.assertFalse(hasattr(obj, 'launch')); self.assertFalse(hasattr(obj, 'executor'))
        self.assertFalse(obj.status()['production_provider'])


if __name__ == '__main__': unittest.main()
