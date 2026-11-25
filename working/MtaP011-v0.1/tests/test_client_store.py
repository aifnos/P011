"""HOST combination of the actual coordination/FILES with trusted FakeOS."""
import ast
import errno
import importlib.util
import os
import socket
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime')))
import mta_client_store as s
import mta_client_coordination as coordination
import mta_client_files as files
import mta_client_journal_codec as codec
import mta_p2p_client_init as core
from test_client_files import FakeIo, Node, TOKEN, RUN, TARGET, PENDING
from test_client_journal_codec import IDENTITY, baseline, record


class Clock(object):
    def __init__(self): self.value = 1.0
    def __call__(self): return self.value


class CombinedIo(FakeIo):
    FLAGS = dict(FakeIo.FLAGS, O_RDWR=2)

    def __init__(self):
        FakeIo.__init__(self)
        self.clock, self.flocks, self.pauses = Clock(), [], []

    def flock(self, fd, flags):
        self.flocks.append((fd, flags))
        self.event('flock', self.handles[fd][0].path)
        return 0, 0

    def pause(self, seconds):
        self.pauses.append(seconds)
        self.clock.value += seconds


class StoreTests(unittest.TestCase):
    def setUp(self):
        for name in ('open', 'read', 'write', 'close', 'stat', 'lstat', 'fstat', 'mkdir',
                     'unlink', 'rename', 'replace', 'fsync', 'kill', 'waitpid', 'fork', 'dup'):
            if hasattr(os, name):
                patcher = mock.patch.object(os, name, side_effect=AssertionError('actual OS forbidden'))
                patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket'):
            patcher = mock.patch(target, side_effect=AssertionError('actual native/network forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)

    def make(self, io=None, **kw):
        io = io or CombinedIo()
        obj = s.ClientPreparationStore(TOKEN, IDENTITY, _coordination_io=io,
            _files_io=io, _clock=io.clock, **kw)
        self.addCleanup(obj.close)
        return obj, io

    def opened(self, io=None):
        obj, io = self.make(io)
        return obj, io, obj.open()

    def reject(self, action, code):
        with self.assertRaises(s.PreparationError) as caught: action()
        self.assertEqual(code, caught.exception.code)
        for private in (TOKEN, RUN, 'private', 'wlan0', '/usr/bin/'):
            self.assertNotIn(private, str(caught.exception))

    def test_import_and_constructor_pure_actual_components(self):
        obj, io = self.make()
        self.assertEqual([], io.ops)
        self.assertIs(type(obj._coordination), coordination.ClientCoordination)
        self.assertIs(type(obj._files), files.ClientJournalFiles)
        spec = importlib.util.spec_from_file_location('host_preparation_store', s.__file__)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        module.ClientPreparationStore(TOKEN, IDENTITY, _coordination_io=io, _files_io=io)
        self.assertEqual([], io.ops)

    def test_python35_ast_no_forbidden_operations_or_full_store(self):
        with open(s.__file__, encoding='utf-8') as source: tree = ast.parse(source.read(), feature_version=(3, 5))
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertFalse({'mkdir', 'unlink', 'fork', 'dup', 'kill', 'waitpid', 'socket', 'finish'} & attrs)
        obj, _ = self.make()
        self.assertNotIsInstance(obj, core.ClientInitStore)
        for name in ('acquire', 'finish', 'restore', 'clear', 'register_inherited', 'pending_matches'):
            self.assertFalse(hasattr(obj, name))

    def test_invalid_config_finite_exact_types_without_io(self):
        for token in ('', '1' * 31, 'A' * 32, '../' + '1' * 29, True):
            self.reject(lambda: s.ClientPreparationStore(token, IDENTITY), 'invalid_config')
        for budget in (True, 0, 11, float('nan'), float('inf'), 10 ** 1000):
            self.reject(lambda: s.ClientPreparationStore(TOKEN, IDENTITY, timeout=budget), 'invalid_config')
        self.reject(lambda: s.ClientPreparationStore(TOKEN, object()), 'invalid_config')

    def test_real_components_lock_before_files_and_empty_current(self):
        obj, io, session = self.opened()
        self.assertIs(type(session), s.PreparationSession)
        opens = [r[0] for r in io.opened]
        self.assertEqual(['/', '/tmp', '/tmp/p011-mta-client-rfinit', RUN,
            '/tmp/p011-mta-p2p-device.lock', RUN + '/journal.lock'], opens[:6])
        self.assertEqual(['/', '/tmp', '/tmp/p011-mta-client-rfinit', RUN], opens[6:])
        self.assertIsNone(obj.current(session))
        self.assertNotIn(TARGET, io.nodes)
        self.assertTrue(all(flags == 6 for _, flags in io.flocks))

    def test_prepare_empty_actual_cas_fsync_rename_and_private_receipt(self):
        obj, io, session = self.opened()
        result = obj.prepare_initial(session, baseline(), 10.0)
        self.assertIs(type(result), s.PreparedFileReceipt)
        self.assertEqual('prepared', result.journal.stage)
        self.assertFalse(result.journal.ready)
        self.assertIsNone(result.journal.owned)
        self.assertEqual(codec.encode_journal(result.journal), io.nodes[TARGET].data)
        self.assertIn(('fsync', RUN + '/journal.00000001.tmp'), io.ops)
        self.assertIn(('rename', RUN + '/journal.00000001.tmp'), io.ops)
        self.assertIn(('fsync', RUN), io.ops)
        self.assertNotIn(PENDING, io.nodes)
        self.assertEqual(result.canonical.data, obj.current(session).data)
        self.assertFalse(obj.status()['baseline_authenticated'])

    def test_old_ready_current_is_data_not_readiness_or_adoption(self):
        io = CombinedIo(); data = codec.encode_journal(record())
        io.add(TARGET, data=data)
        obj, io, session = self.opened(io)
        observed = obj.current(session)
        self.assertTrue(observed.journal.ready)
        self.assertFalse(obj.status()['rf_admission'])
        self.assertFalse(obj.status()['prepared_checkpoint'])
        self.reject(lambda: obj.prepare_initial(session, baseline(), 10), 'current_exists')
        self.assertEqual(data, io.nodes[TARGET].data)
        self.assertFalse(any(action in ('write', 'rename') for action, _ in io.ops))

    def test_existing_prepared_also_never_overwritten(self):
        io = CombinedIo(); data = codec.encode_journal(record('prepared'))
        io.add(TARGET, data=data)
        obj, io, session = self.opened(io)
        self.reject(lambda: obj.prepare_initial(session, baseline(), 10), 'current_exists')
        self.assertEqual(data, io.nodes[TARGET].data)

    def test_foreign_or_forged_session_no_owner_side_effects(self):
        obj, io, session = self.opened()
        other, _ = self.make()
        self.reject(lambda: other.current(session), 'invalid_session')
        forged = s.PreparationSession(obj._issuer, 1)
        before = list(io.ops)
        self.reject(lambda: obj.current(forged), 'invalid_session')
        self.reject(lambda: obj.close(forged), 'invalid_session')
        self.assertEqual(before, io.ops)
        self.assertTrue(obj.status()['opened'])

    def test_invalid_baseline_and_deadline_before_backend_io(self):
        obj, io, session = self.opened()
        before = list(io.ops)
        self.reject(lambda: obj.prepare_initial(session, object(), 10), 'invalid_baseline')
        for deadline in (True, float('nan'), float('inf'), 10 ** 1000, -1):
            self.reject(lambda: obj.prepare_initial(session, baseline(), deadline), 'invalid_deadline')
        self.assertEqual(before, io.ops)
        self.assertFalse(obj.status()['prepare_attempted'])

    def test_second_initial_prepare_never_writes_or_rebases(self):
        obj, io, session = self.opened()
        obj.prepare_initial(session, baseline(), 10)
        before = list(io.ops)
        self.reject(lambda: obj.prepare_initial(session, baseline(), 11), 'prepare_already_attempted')
        self.assertEqual(before, io.ops)

    def test_pending_existing_blocks_actual_acquire_no_marker_change(self):
        io = CombinedIo(); node = io.add(PENDING, data=b'old-private-marker')
        obj, _ = self.make(io)
        self.reject(obj.open, 'component_error')
        self.assertIs(node, io.nodes[PENDING])
        self.assertEqual([], io.flocks)
        self.assertFalse(obj.status()['pending_modified'])

    def test_pending_appears_before_files_open_closes_both(self):
        io = CombinedIo()
        def hook(value, operation, path, count):
            if operation == 'stat' and path == PENDING and count == 4: value.add(PENDING)
        io.hook = hook
        obj, _ = self.make(io)
        self.reject(obj.open, 'component_error')
        self.assertIn(PENDING, io.nodes)
        self.assertEqual({}, io.handles)
        self.assertEqual(len(io.closed), len(set(io.closed)))

    def test_pending_after_open_blocks_preparation_and_keeps_entry(self):
        obj, io, session = self.opened()
        io.add(PENDING)
        self.reject(lambda: obj.prepare_initial(session, baseline(), 10), 'component_error')
        self.assertNotIn(TARGET, io.nodes)
        self.assertIn(PENDING, io.nodes)
        self.assertEqual({}, io.handles)

    def test_lock_entry_changes_before_prepare_no_journal_write(self):
        obj, io, session = self.opened()
        io.nodes['/tmp/p011-mta-p2p-device.lock'].ino += 1000
        self.reject(lambda: obj.prepare_initial(session, baseline(), 10), 'component_error')
        self.assertNotIn(TARGET, io.nodes)

    def test_global_deadline_shared_with_inner_write_and_no_extension(self):
        obj, io, session = self.opened()
        def hook(value, operation, path, count):
            if operation == 'write': value.clock.value = 4.5
        io.hook = hook
        self.reject(lambda: obj.prepare_initial(session, baseline(), 10), 'expired')
        self.assertNotIn(TARGET, io.nodes)
        self.assertTrue(obj.status()['checkpoint_unverified'])
        self.assertTrue(obj.status()['write_pending'])
        self.assertEqual({}, io.handles)
        self.assertFalse(obj.close(session).complete())

    def test_expired_journal_deadline_rejects_without_write(self):
        obj, io, session = self.opened()
        self.reject(lambda: obj.prepare_initial(session, baseline(), 1), 'invalid_deadline')
        self.assertFalse(any(action == 'write' for action, _ in io.ops))
        self.assertEqual({}, io.handles)

    def test_clock_regression_after_open_fails_before_publication(self):
        obj, io, session = self.opened()
        io.clock.value = 0.5
        self.reject(lambda: obj.current(session), 'clock_regressed')
        self.assertEqual({}, io.handles)
        self.assertTrue(obj.status()['resource_pending'])

    def test_file_fsync_failure_preserves_actual_temp_and_pending(self):
        obj, io, session = self.opened()
        io.faults[('fsync', RUN + '/journal.00000001.tmp')] = OSError(errno.EIO, 'private failure')
        self.reject(lambda: obj.prepare_initial(session, baseline(), 10), 'component_error')
        self.assertIn(RUN + '/journal.00000001.tmp', io.nodes)
        self.assertNotIn(TARGET, io.nodes)
        self.assertTrue(obj.status()['write_pending'])
        self.assertFalse(obj.close(session).complete())

    def test_directory_fsync_failure_retains_publication_unknown(self):
        obj, io, session = self.opened()
        io.faults[('fsync', RUN)] = OSError(errno.EIO, 'private directory failure')
        self.reject(lambda: obj.prepare_initial(session, baseline(), 10), 'component_error')
        self.assertIn(TARGET, io.nodes)
        self.assertTrue(obj.status()['published_unknown'])
        self.assertTrue(obj.status()['checkpoint_unverified'])
        self.assertFalse(obj.status()['prepared_checkpoint'])

    def test_postcommit_lock_failure_retains_exact_candidate(self):
        obj, io, session = self.opened()
        original = obj._coordination.validate
        calls = []
        def gate(value):
            calls.append(value)
            result = original(value)
            if len(calls) == 3: raise OSError(errno.EIO, 'private postcommit')
            return result
        with mock.patch.object(obj._coordination, 'validate', side_effect=gate):
            self.reject(lambda: obj.prepare_initial(session, baseline(), 10), 'component_error')
        self.assertIs(type(obj._committed_candidate), files.CanonicalRecord)
        self.assertEqual(io.nodes[TARGET].data, obj._committed_candidate.data)
        self.assertTrue(obj.status()['checkpoint_unverified'])
        self.assertFalse(obj.close(session).complete())

    def test_final_readback_metadata_change_rejected(self):
        obj, io, session = self.opened()
        original = obj._coordination.validate
        calls = []
        def gate(value):
            result = original(value); calls.append(value)
            if len(calls) == 3: io.nodes[TARGET].stamp += 1
            return result
        with mock.patch.object(obj._coordination, 'validate', side_effect=gate):
            self.reject(lambda: obj.prepare_initial(session, baseline(), 10), 'readback_changed')
        self.assertFalse(obj.status()['prepared_checkpoint'])
        self.assertTrue(obj.status()['checkpoint_unverified'])

    def test_close_success_all_original_resources_fresh_observed(self):
        obj, io, session = self.opened()
        obj.prepare_initial(session, baseline(), 10)
        receipt = obj.close(session)
        self.assertIs(type(receipt), s.PreparationCloseObservation)
        self.assertTrue(receipt.complete())
        self.assertTrue(receipt.files_closed)
        self.assertTrue(receipt.coordination_closed)
        self.assertEqual({}, io.handles)
        self.assertEqual(len(io.opened), len(set(io.closed)))
        self.assertFalse(obj.status()['full_store_implemented'])

    def test_close_component_exception_still_closes_other_exact_owner(self):
        obj, io, session = self.opened()
        with mock.patch.object(obj._files, 'close', side_effect=KeyboardInterrupt('private interrupt')) as action:
            result = obj.close(session)
            self.assertTrue(result.resource_pending)
            self.assertFalse(result.complete())
            self.assertTrue(all(t.closed for t in obj._coordination._inventory))
            obj.close(session)
            self.assertEqual(1, action.call_count)
        self.assertTrue(io.handles)  # Unknown FILES references remain, no blind retry.
        self.assertIs(obj._files._io, io)

    def test_fabricated_close_status_cannot_replace_actual_inventory(self):
        obj, io, session = self.opened()
        with mock.patch.object(obj._files, 'close', return_value={'all_owned_fds_closed': True}):
            receipt = obj.close(session)
        self.assertFalse(receipt.files_closed)
        self.assertFalse(receipt.complete())
        self.assertTrue(receipt.resource_pending)
        self.assertTrue(io.handles)

    def test_unknown_files_open_keeps_both_component_refs_no_reopen(self):
        obj, io = self.make()
        original = io.open_at
        run_calls = []
        def unknown(parent, name, flags, mode=0):
            if name == 'client-' + TOKEN:
                run_calls.append(name)
                if len(run_calls) == 2: raise MemoryError('private files creation')
            return original(parent, name, flags, mode)
        io.open_at = unknown
        self.reject(obj.open, 'component_error')
        self.assertTrue(obj.status()['resource_pending'])
        self.assertTrue(any(t.opening_unknown for t in obj._files._inventory))
        self.assertIs(obj._files._io, io)
        self.assertIs(obj._coordination._io, io)
        count = len(io.opened); obj.close()
        self.assertEqual(count, len(io.opened))
        self.reject(obj.open, 'already_attempted')

    def test_original_fd_reuse_never_reclosed_by_combined_owner(self):
        obj, io, session = self.opened()
        fd = obj._files._inventory[0].fd
        original = io.close
        def replacement(value):
            original(value)
            if value == fd: io.handles[value] = [Node('/private/replacement', 0o100600, 999), 0]
        io.close = replacement
        result = obj.close(session)
        self.assertTrue(result.resource_pending)
        before = list(io.closed); obj.close(session)
        self.assertEqual(before, io.closed)
        self.assertIn(fd, io.handles)

    def test_repeat_close_is_only_observation_no_close_open_flock(self):
        obj, io, session = self.opened()
        obj.close(session)
        calls, opened, flocks = list(io.closed), list(io.opened), list(io.flocks)
        self.assertTrue(obj.close(session).complete())
        self.assertEqual(calls, io.closed)
        self.assertEqual(opened, io.opened)
        self.assertEqual(flocks, io.flocks)

    def test_close_before_open_not_zero_resource_completion(self):
        obj, io = self.make()
        self.assertFalse(obj.close().complete())
        self.assertEqual([], io.ops)
        self.reject(obj.open, 'already_attempted')

    def test_public_projection_private_receipts_and_no_capability_upgrade(self):
        obj, io, session = self.opened()
        receipt = obj.prepare_initial(session, baseline(), 10)
        public = str(obj.status()) + repr(session) + repr(receipt) + repr(obj.close(session))
        for private in (TOKEN, RUN, IDENTITY.candidate_sha, 'wlan0', '/usr/bin/', 'argv_sha'):
            self.assertNotIn(private, public)
        for key in ('baseline_authenticated', 'executor_verified', 'same_ofd_verified', 'pending_modified',
                    'rf_admission', 'full_store_implemented', 'receive_available', 'send_available'):
            self.assertIs(obj.status()[key], False)


if __name__ == '__main__': unittest.main()
