"""Real component methods over synthetic filesystem/process/restore producer.

No OS/WSL/P011/network evidence. Restore observations below are explicitly
HOST-only; no positive guard/binding is mocked into an authorization boolean.
"""
import ast
import errno
import os
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime')))
import mta_client_pending as p
import mta_client_files as f
import mta_client_coordination as c
import mta_client_proc as proc
import mta_client_store as stores
import mta_p2p_client_init as core
from test_client_journal_transaction import CombinedIo
from test_client_pending import Reader
from test_client_files import TOKEN, PENDING, TARGET, RUN, BASE
from test_client_journal_codec import baseline, IDENTITY


class ClearIo(CombinedIo):
    def __init__(self):
        CombinedIo.__init__(self)
        self.unlinks, self.unlink_result, self.after_unlink = [], (0, 0), None
        self.ctimes = {}

    def fstat(self, fd):
        value = CombinedIo.fstat(self, fd)
        node = self.handles[fd][0]
        if node.ino in self.ctimes:
            value = types.SimpleNamespace(**vars(value))
            value.st_ctime_ns = self.ctimes[node.ino]
        return value

    def unlink_at(self, parent, name):
        path = self.path(parent, name)
        self.unlinks.append((parent, name))
        self.event('unlink', path)
        if self.unlink_result != (0, 0): return self.unlink_result
        node = self.nodes.pop(path)
        node.links = 0
        self.ctimes[node.ino] = node.stamp + 1
        if self.after_unlink: self.after_unlink(self, node)
        return (0, 0)


class RestoreReader(object):
    """Explicit Fake producer with exact returned-tuple issuance, not kernel proof."""
    def __init__(self): self.issued, self.calls, self.authenticate_calls = [], 0, 0

    def read_restore(self, store, locks, record, deadline):
        value = (baseline(), core.CloseProof(1, (True,), (True,)))
        self.issued.append((store, locks, record, value))
        self.calls += 1
        return value

    def authenticate_restore(self, store, locks, record, value, deadline):
        self.authenticate_calls += 1
        if not any(s is store and l is locks and r is record and v is value
                   for s, l, r, v in self.issued):
            raise ValueError('synthetic_unissued')
        return None


class PendingClearTests(unittest.TestCase):
    def setUp(self):
        for cls in (c._LinuxIo, f._LinuxIo, p._LinuxIo):
            for name in ('validate', 'open_root', 'open_at', 'stat_at', 'fstat',
                         'read', 'write', 'seek_start', 'fsync', 'rename_at',
                         'unlink_at', 'close', 'flock'):
                if hasattr(cls, name):
                    patcher = mock.patch.object(cls, name, side_effect=AssertionError('actual OS forbidden'))
                    patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket'):
            patcher = mock.patch(target, side_effect=AssertionError('actual native/network forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(proc.ProcReader, 'read_self', side_effect=AssertionError('actual proc forbidden'))
        patcher.start(); self.addCleanup(patcher.stop)

    def make(self, producer=True):
        io, reader = ClearIo(), Reader()
        reader.boot = baseline().boot
        restored = RestoreReader() if producer else None
        store = stores.DurableClientInitStore(TOKEN, IDENTITY,
            _coordination_io=io, _files_io=io, _pending_io=io,
            _proc_reader=reader, _clock=io.clock, _restore_reader=restored)
        locks = store.acquire(IDENTITY, 3.0)
        current = store.commit(locks, core.Journal(IDENTITY, 'prepared', baseline(), 10.0))
        current = store.commit(locks, current.replace(stage='cleanup_intent'))
        current = store.commit(locks, current.replace(stage='cleanup_verified'))
        self.addCleanup(store._coordination.close)
        self.addCleanup(store._files.close)
        self.addCleanup(store._marker.close)
        return store, locks, current, io, reader, restored

    def finish(self, values, before=None, after=None):
        store, locks, record, io, _, _ = values
        marker = store._marker
        original, captured = marker.clear_terminal, {}
        def clear(s, b, canonical, deadline):
            if before: before(s, b, canonical, deadline)
            value = original(s, b, canonical, deadline)
            captured['facts'] = value
            captured['closed'] = tuple(io.closed)
            captured['marker_fd_open'] = marker._ticket.fd in io.handles
            captured['refs'] = marker._clear_refs
            if after: after(s, b, canonical, deadline, value)
            return value
        with mock.patch.object(marker, 'clear_terminal', side_effect=clear):
            captured['finish'] = store.finish(locks, record, True, 3.0)
        return captured

    def test_actual_component_clear_once_absent_verified_before_any_fd_close(self):
        values = self.make(); store, _, _, io, _, producer = values
        before = tuple(io.closed)
        captured = self.finish(values)
        facts = captured['facts']
        self.assertEqual({'marker_state', 'clear_durability', 'clear_attempted', 'reason', 'resource_pending'}, set(facts))
        self.assertEqual('absent_observed', facts['marker_state'])
        self.assertEqual('verified', facts['clear_durability'])
        self.assertTrue(facts['clear_attempted']); self.assertFalse(facts['resource_pending'])
        # FILES readback opens are independently closed, but marker/anchors/locks
        # stay open until the concrete Store's later inventory-close phase.
        self.assertTrue(captured['marker_fd_open']); self.assertNotIn(store._marker._ticket.fd, captured['closed'])
        self.assertTrue(set(before) <= set(captured['closed']))
        self.assertEqual(1, len(io.unlinks)); self.assertEqual(c.GLOBAL_PENDING, io.unlinks[0][1])
        self.assertNotIn(PENDING, io.nodes); self.assertIn(TARGET, io.nodes)
        self.assertGreaterEqual(producer.calls, 2); self.assertEqual(producer.calls, producer.authenticate_calls)
        self.assertTrue(captured['finish'].complete)

    def test_default_missing_restore_producer_retains_marker(self):
        values = self.make(producer=False)
        result = self.finish(values)
        self.assertIn(PENDING, values[3].nodes); self.assertEqual([], values[3].unlinks)
        self.assertFalse(result['finish'].complete)

    def test_status_passive_and_repeat_zero_io(self):
        values = self.make(); store, _, _, io, _, _ = values
        def after(s, b, canonical, deadline, value):
            before = list(io.ops), list(io.opened), list(io.closed), list(io.unlinks)
            self.assertEqual(value, s._marker.clear_status())
            with self.assertRaises(p.PendingError) as error:
                s._marker.clear_terminal(s, b, canonical, deadline)
            self.assertEqual('already_attempted', error.exception.code)
            self.assertEqual(before, (io.ops, io.opened, io.closed, io.unlinks))
        self.finish(values, after=after)

    def test_sealed_ordinary_guards_cannot_resume_file_admission(self):
        values = self.make()
        def after(s, b, canonical, deadline, value):
            for action in (s._marker.verify, lambda: b.verify(s._files, s._epoch),
                           lambda: s._files.commit(canonical, canonical.journal),
                           lambda: s._coordination.validate(s._current_locks)):
                with self.assertRaises(ValueError): action()
            self.assertFalse(s._marker.status()['local_binding_issued'])
        self.finish(values, after=after)

    def test_same_bytes_changed_marker_inode_never_unlinks(self):
        values = self.make()
        def before(s, b, canonical, deadline):
            node = values[3].nodes[PENDING]
            replacement = values[3].add(PENDING, data=node.data)
            replacement.ino = node.ino + 100
        result = self.finish(values, before=before)
        self.assertFalse(result['facts']['clear_attempted']); self.assertEqual([], values[3].unlinks)

    def test_changed_marker_bytes_owner_or_linkcount_never_unlinks(self):
        for field in ('bytes', 'uid', 'links'):
            values = self.make()
            def before(s, b, canonical, deadline):
                node = values[3].nodes[PENDING]
                if field == 'bytes': node.data = b'old-GO-or-secret'
                elif field == 'uid': node.uid = 1
                else: node.links = 2
            result = self.finish(values, before=before)
            self.assertFalse(result['facts']['clear_attempted']); self.assertEqual([], values[3].unlinks)

    def test_fresh_owner_boot_change_prevents_unlink(self):
        for field in ('boot', 'actor'):
            values = self.make()
            def before(s, b, canonical, deadline):
                if field == 'boot': values[4].boot = '2' * 8 + '-2222-2222-2222-' + '2' * 12
                else: values[4].actor = core.Actor(123, 301, '/usr/bin/python3', 'b' * 64, ((123, 301, 'S'),))
            result = self.finish(values, before=before)
            self.assertFalse(result['facts']['clear_attempted']); self.assertEqual([], values[3].unlinks)

    def test_each_directory_anchor_and_lock_replacement_prevents_unlink(self):
        for path in ('/', '/tmp', BASE, RUN, '/tmp/' + c.DEVICE_LOCK, RUN + '/' + c.JOURNAL_LOCK):
            values = self.make()
            def before(s, b, canonical, deadline): values[3].nodes[path].ino += 100
            result = self.finish(values, before=before)
            self.assertFalse(result['facts']['clear_attempted']); self.assertEqual([], values[3].unlinks)

    def test_canonical_same_bytes_replaced_inode_prevents_unlink(self):
        values = self.make()
        def before(s, b, canonical, deadline): values[3].nodes[TARGET].ino += 100
        result = self.finish(values, before=before)
        self.assertFalse(result['facts']['clear_attempted']); self.assertEqual([], values[3].unlinks)

    def test_current_journal_epoch_mismatch_prevents_unlink(self):
        values = self.make()
        def before(s, b, canonical, deadline): s._journal_epoch = object()
        result = self.finish(values, before=before)
        self.assertFalse(result['facts']['clear_attempted']); self.assertEqual([], values[3].unlinks)

    def test_store_binding_epoch_lock_or_canonical_mismatch_prevents_unlink(self):
        for field in ('_epoch', '_current_locks', '_canonical', '_terminal_canonical'):
            values = self.make()
            def before(s, b, canonical, deadline): setattr(s, field, object())
            result = self.finish(values, before=before)
            self.assertFalse(result['facts']['clear_attempted']); self.assertEqual([], values[3].unlinks)

    def test_constructed_receipt_or_bool_is_not_store(self):
        values = self.make(); store = values[0]
        for wrong in (True, False, object()):
            with self.assertRaises(p.PendingError):
                store._marker.clear_terminal(wrong, store._binding, store._canonical, 3.0)
        self.assertFalse(store._marker._clear_requested); self.assertEqual([], values[3].unlinks)

    def test_forged_equal_binding_or_canonical_not_issuer_registered(self):
        values = self.make(); store = values[0]; old = store._binding
        forged = p.OwnedMarkerBinding(old._issuer, old._marker, old._coordination,
            old._files, old._prepared, old._epoch, old._serialization_lock)
        with self.assertRaises(p.PendingError): store._marker.clear_terminal(store, forged, store._canonical, 3.0)
        self.assertFalse(store._marker._clear_requested)
        def before(s, b, canonical, deadline):
            fake = f.CanonicalRecord(canonical.journal, canonical.data, canonical.metadata,
                canonical._issuer, canonical._generation)
            s._canonical = s._terminal_canonical = fake
        result = self.finish(values, before=before)
        self.assertEqual([], values[3].unlinks); self.assertFalse(result['facts']['clear_attempted'])

    def test_authorization_boolean_return_is_rejected(self):
        values = self.make()
        with mock.patch.object(stores.DurableClientInitStore, '_authorize_terminal_clear', return_value=True):
            result = self.finish(values)
        self.assertEqual('clear_not_authorized', result['facts']['reason']); self.assertEqual([], values[3].unlinks)

    def test_unlink_error_unknown_keeps_refs_and_never_retries(self):
        for error in (OSError(errno.EIO, 'secret'), MemoryError('secret')):
            values = self.make(); values[3].faults[('unlink', PENDING)] = error
            result = self.finish(values)
            self.assertEqual('unknown', result['facts']['clear_durability'])
            self.assertEqual('retained_observed', result['facts']['marker_state'])
            self.assertIs(result['refs'][0], values[0]); self.assertEqual(1, len(values[3].unlinks))
            self.assertIn(PENDING, values[3].nodes); self.assertFalse(result['finish'].complete)

    def test_malformed_unlink_result_failclosed(self):
        for value in (None, True, (True, 0), (0, True), (0, 1), (-1, errno.EIO), (0, 0, 0)):
            values = self.make(); values[3].unlink_result = value
            result = self.finish(values)
            self.assertEqual('unknown', result['facts']['clear_durability'])
            self.assertFalse(result['finish'].complete); self.assertEqual(1, len(values[3].unlinks))

    def test_successful_unlink_then_fsync_error_truthful_absent_not_complete(self):
        values = self.make()
        def before(s, b, canonical, deadline): values[3].faults[('fsync', '/tmp')] = OSError(errno.EIO, 'secret')
        result = self.finish(values, before=before)
        self.assertEqual('absent_observed', result['facts']['marker_state'])
        self.assertEqual('unknown', result['facts']['clear_durability'])
        self.assertFalse(result['finish'].complete); self.assertNotIn(PENDING, values[3].nodes)

    def test_absence_error_not_enoent_is_unknown(self):
        values = self.make()
        def after_unlink(io, node): io.faults[('stat', PENDING)] = OSError(errno.EACCES, 'secret')
        values[3].after_unlink = after_unlink
        result = self.finish(values)
        self.assertEqual('unknown', result['facts']['marker_state']); self.assertFalse(result['finish'].complete)

    def test_post_unlink_replacement_is_not_retained_own_marker(self):
        values = self.make()
        def after_unlink(io, node): io.add(PENDING, data=node.data)
        values[3].after_unlink = after_unlink
        result = self.finish(values)
        self.assertEqual('unknown', result['facts']['marker_state']); self.assertFalse(result['finish'].complete)
        self.assertIn(PENDING, values[3].nodes); self.assertEqual(1, len(values[3].unlinks))

    def test_post_unlink_fd_mutation_prevents_verified(self):
        for field in ('bytes', 'mtime', 'links', 'ino'):
            values = self.make()
            def after_unlink(io, node):
                if field == 'bytes': node.data = b'secret'
                elif field == 'mtime': node.stamp += 1
                elif field == 'links': node.links = 1
                else: node.ino += 1
            values[3].after_unlink = after_unlink
            result = self.finish(values)
            self.assertEqual('absent_observed', result['facts']['marker_state'])
            self.assertEqual('unknown', result['facts']['clear_durability']); self.assertFalse(result['finish'].complete)

    def test_post_unlink_anchor_mutation_prevents_verified(self):
        values = self.make()
        values[3].after_unlink = lambda io, node: setattr(io.nodes[RUN], 'ino', io.nodes[RUN].ino + 1)
        result = self.finish(values)
        self.assertEqual('unknown', result['facts']['clear_durability']); self.assertFalse(result['finish'].complete)

    def test_baseexception_after_unlink_preserves_absent_unknown_and_refs(self):
        values = self.make()
        def after_unlink(io, node): raise KeyboardInterrupt()
        values[3].after_unlink = after_unlink
        with self.assertRaises(KeyboardInterrupt): self.finish(values)
        marker = values[0]._marker
        self.assertEqual('absent_observed', marker.clear_status()['marker_state'])
        self.assertEqual('unknown', marker.clear_status()['clear_durability'])
        self.assertIs(marker._clear_refs[0], values[0]); self.assertTrue(marker._clear_sealed)
        count = len(values[3].ops)
        with self.assertRaises(p.PendingError): marker.clear_terminal(values[0], values[0]._binding, values[0]._canonical, 3.0)
        self.assertEqual(count, len(values[3].ops))

    def test_expiry_before_unlink_and_after_unlink_no_extra_write(self):
        for timing in ('before', 'after'):
            values = self.make()
            if timing == 'before':
                before = lambda s, b, canonical, deadline: setattr(values[3].clock, 'value', 4.0)
            else:
                before = None
                values[3].after_unlink = lambda io, node: setattr(io.clock, 'value', 4.0)
            result = self.finish(values, before=before)
            self.assertEqual(0 if timing == 'before' else 1, len(values[3].unlinks))
            self.assertNotEqual('verified', result['facts']['clear_durability']); self.assertFalse(result['finish'].complete)

    def test_foreign_marker_or_closed_original_blocks_without_new_open(self):
        for change in ('closed', 'foreign'):
            values = self.make()
            def before(s, b, canonical, deadline):
                if change == 'closed': s._marker.close()
                else: values[3].nodes[PENDING].data = b'old-global-GO'
            result = self.finish(values, before=before)
            self.assertEqual([], values[3].unlinks); self.assertFalse(result['finish'].complete)

    def test_every_clear_io_same_shared_outer_domain(self):
        values = self.make(); store, _, _, io, _, _ = values
        io.hook = lambda io, operation, path, count: self.assertTrue(store._mutex._is_owned())
        self.finish(values)
        io.hook = None

    def test_public_facts_never_expose_private_values(self):
        values = self.make()
        result = self.finish(values)
        text = repr(result['facts']) + repr(values[0]._marker.status())
        for secret in (TOKEN, PENDING, baseline().boot, IDENTITY.candidate_sha, 'wlan0', 'argv_sha'):
            self.assertNotIn(secret, text)

    def test_python35_scope_only_fixed_unlink_no_rf_or_assert(self):
        with open(p.__file__, encoding='utf-8') as source: tree = ast.parse(source.read(), feature_version=(3, 5))
        forbidden = {'unlink', 'mkdir', 'rename', 'fork', 'kill', 'socket', 'waitpid', 'dup', 'system', 'Popen'}
        self.assertFalse(forbidden & {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)})
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        unlink_c = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'unlinkat']
        unlink_io = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'unlink_at']
        self.assertEqual(1, len(unlink_c)); self.assertEqual(1, len(unlink_io))
        for name in ('clear', 'restore', 'finish'): self.assertFalse(hasattr(p.ClientPendingMarker, name))


if __name__ == '__main__': unittest.main()
