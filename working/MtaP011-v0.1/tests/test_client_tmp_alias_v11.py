"""HOST FakeIO candidate composition only; no actual filesystem/locks/proc."""
import ast
import builtins
import errno
import os
from pathlib import Path
import stat
import sys
import threading
import types
import unittest
from unittest import mock

BASE_PATH = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_PATH / 'runtime'))
from test_client_journal_transaction import CombinedIo
from test_client_files import TOKEN, RUN, BASE, PENDING
from test_client_pending import Reader
from test_client_journal_codec import baseline, IDENTITY
import mta_p2p_client_init as core
import mta_client_proc as proc

MODULE_PATH = BASE_PATH / 'candidate/client-tmp-alias-v11/runtime'
graph = {}


def _load(name, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    original = builtins.__import__
    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if not level and name in graph: return graph[name]
        return original(name, globals, locals, fromlist, level)
    module.__dict__['__builtins__'] = dict(vars(builtins), __import__=imports)
    graph[name] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


a = _load('mta_client_tmp_alias', MODULE_PATH / 'mta_client_tmp_alias.py')
c = _load('mta_client_coordination', MODULE_PATH / 'mta_client_coordination.py')
f = _load('mta_client_files', MODULE_PATH / 'mta_client_files.py')
p = _load('mta_client_pending', BASE_PATH / 'candidate/client-recovery-budget-v8/runtime/mta_client_pending.py')
PHYSICAL_BASE = a.PHYSICAL_TMP + '/' + c.BASE
PHYSICAL_RUN = PHYSICAL_BASE + '/' + c.RUN_PREFIX + TOKEN
PHYSICAL_PENDING = a.PHYSICAL_TMP + '/' + c.GLOBAL_PENDING


class AliasIo(CombinedIo):
    def __init__(self, alias=True):
        CombinedIo.__init__(self)
        self.alias = alias
        if alias:
            for path in tuple(self.nodes):
                if path == '/tmp' or path.startswith('/tmp/'):
                    node = self.nodes.pop(path)
                    node.path = a.PHYSICAL_TMP + path[4:]
                    self.nodes[node.path] = node
            self.add('/var', stat.S_IFDIR | 0o755)
            self.add('/var/volatile', stat.S_IFDIR | 0o1777)
            self.add('/tmp', stat.S_IFLNK | 0o777, b'/var/tmp')
            self.add('/var/tmp', stat.S_IFLNK | 0o777, a.PHYSICAL_TMP.encode('ascii'))
        self.borrow_path = self.unknown_path = None

    def stat_root(self):
        self.event('stat_root', '/')
        return self.nodes['/'].metadata()

    def readlink_at(self, parent, name):
        path = self.path(parent, name)
        self.event('readlink', path)
        node = self.nodes[path]
        if not stat.S_ISLNK(node.mode): raise OSError(errno.EINVAL, 'HOST not a link')
        return node.data.decode('ascii')

    def _open(self, path, flags, mode):
        if path == self.unknown_path:
            self.event('open', path)
            raise MemoryError('HOST unknown open outcome')
        if path == self.borrow_path:
            self.event('open', path)
            return next(fd for fd, (node, unused) in self.handles.items() if node.path == '/')
        node = self.nodes.get(path)
        if node is not None and flags & self.FLAGS['O_NOFOLLOW'] and stat.S_ISLNK(node.mode):
            raise OSError(errno.ELOOP, 'HOST nofollow')
        if node is not None and flags & self.FLAGS['O_DIRECTORY'] and not stat.S_ISDIR(node.mode):
            raise OSError(errno.ENOTDIR, 'HOST directory required')
        return CombinedIo._open(self, path, flags, mode)


class TmpAliasV11Tests(unittest.TestCase):
    def setUp(self):
        for cls in (c._LinuxIo, f._LinuxIo, p._LinuxIo):
            for name in ('validate', 'open_root', 'open_at', 'stat_at', 'stat_root', 'readlink_at',
                         'fstat', 'close', 'read', 'write', 'fsync', 'flock', 'rename_at'):
                if hasattr(cls, name):
                    patcher = mock.patch.object(cls, name, side_effect=AssertionError('actual OS forbidden'))
                    patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket'):
            patcher = mock.patch(target, side_effect=AssertionError('actual native/network forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(proc.ProcReader, 'read_self', side_effect=AssertionError('actual proc forbidden'))
        patcher.start(); self.addCleanup(patcher.stop)

    def coord(self, io=None, **kw):
        io = io or AliasIo()
        value = c.ClientCoordination(TOKEN, IDENTITY, _io=io, _clock=io.clock, **kw)
        self.addCleanup(value.close)
        return value, io

    def files(self, io=None, **kw):
        io = io or AliasIo()
        value = f.ClientJournalFiles(TOKEN, IDENTITY, _io=io, _clock=io.clock, **kw)
        self.addCleanup(value.close)
        return value, io

    def actual_binding(self, alias):
        io, shared, epoch = AliasIo(alias), threading.RLock(), object()
        coord, unused = self.coord(io, _serialization_lock=shared)
        locks = coord.acquire()
        files, unused = self.files(io, _serialization_lock=shared)
        files.open()
        canonical = files.commit(None, core.Journal(IDENTITY, 'prepared', baseline(), 10.0))
        reader = Reader(); reader.boot = baseline().boot
        marker = p.ClientPendingMarker(coord, locks, _io=io, _reader=reader,
            _clock=io.clock, _serialization_lock=shared)
        self.addCleanup(marker.close)
        marker.create()
        binding = marker.bind_files(files, canonical, epoch, shared)
        return coord, locks, files, marker, binding, epoch, io

    def test_pure_constructors_python35_and_no_mutation_helper(self):
        io = AliasIo()
        co, unused = self.coord(io); jf, unused = self.files(io)
        anchor = a.FixedTmpAnchor(co, io, object(), co._tmp_fd, co._tmp_open_dir, co._check)
        self.assertFalse(io.ops); self.assertFalse(anchor.prefix_tickets)
        for module in (a, c, f):
            tree = ast.parse(Path(module.__file__).read_text(encoding='utf-8'), feature_version=(3, 5))
            self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))
        helper_tree = ast.parse(Path(a.__file__).read_text(encoding='utf-8'))
        forbidden = {'close', 'mkdir', 'unlink', 'rename', 'chmod', 'kill', 'fork', 'dup', 'socket', 'open'}
        self.assertFalse(forbidden & {n.attr for n in ast.walk(helper_tree) if isinstance(n, ast.Attribute)})
        self.assertEqual(6, c.MAX_RESOURCES); self.assertEqual(8, c.FIXED_ALIAS_RESOURCES)
        self.assertEqual(256, f.MAX_RESOURCES)

    def test_coord_alias_eight_originals_four_logical_and_no_link_open(self):
        co, io = self.coord(); locks = co.acquire()
        self.assertEqual(4, len(co._anchors)); self.assertEqual(8, len(co._inventory))
        self.assertIs(co._anchors[1][1], co._tmp_alias.tmp_parent)
        self.assertIs(locks._device.parent, co._anchors[1][0])
        self.assertIs(locks._journal.parent, co._anchors[3][0])
        self.assertEqual(PHYSICAL_RUN, io.handles[co._anchors[3][0].fd][0].path)
        self.assertEqual(2, len(co._tmp_alias.prefix_tickets))
        self.assertTrue(co.validate(locks)); self.assertTrue(co.read_pending(locks)['entry_absent_observed'])
        for path, flags, mode, fd in io.opened:
            self.assertNotIn(path, ('/tmp', '/var/tmp'))
            self.assertTrue(flags & io.FLAGS['O_NOFOLLOW']); self.assertTrue(flags & io.FLAGS['O_CLOEXEC'])
        self.assertNotIn(PHYSICAL_PENDING, io.nodes)

    def test_files_alias_six_originals_current_empty_no_write(self):
        jf, io = self.files(); self.assertIs(jf.open(), jf)
        self.assertEqual(4, len(jf._anchors)); self.assertEqual(6, len(jf._inventory))
        self.assertIs(jf._anchors[1][1], jf._tmp_alias.tmp_parent)
        self.assertIsNone(jf.read_current())
        self.assertFalse({'write', 'rename', 'fsync'} & {op for op, unused in io.ops})
        self.assertTrue(jf.close()['all_owned_fds_closed']); self.assertFalse(io.handles)

    def test_ordinary_tmp_four_anchors_six_capacity_unchanged(self):
        co, io = self.coord(AliasIo(False)); co.acquire()
        self.assertIsNone(co._tmp_alias); self.assertEqual(6, len(co._inventory))
        before = tuple(io.opened)
        with self.assertRaises(c.CoordinationError): co._open(None, None, 0)
        self.assertEqual(before, tuple(io.opened))
        jf, unused = self.files(AliasIo(False)); jf.open()
        self.assertEqual(4, len(jf._inventory)); self.assertIsNone(jf._tmp_alias)

    def test_real_binding_alias_ninth_handoff_device_last_and_history(self):
        co, old, jf, marker, binding, epoch, io = self.actual_binding(True)
        released = co.release_journal_handoff(old, binding, epoch, 3.0)
        reacquired = co.reacquire_journal(released, 3.0)
        self.assertIs(reacquired.locks._device, old._device)
        self.assertEqual(9, len(co._inventory)); self.assertEqual(4, len(co._anchors))
        self.assertTrue(co.validate(reacquired.locks))
        marker.close(); jf.close(); co.close_device_last()
        self.assertEqual(old._device.fd, io.closed[-1])
        self.assertTrue(co.read_closed(old).complete())
        self.assertTrue(co.read_closed(reacquired.locks).complete())
        self.assertEqual(len(io.closed), len(set(io.closed))); self.assertFalse(io.handles)
        self.assertIn(PHYSICAL_PENDING, io.nodes)  # No clear or claimed restoration.

    def test_real_binding_ordinary_still_seventh_only(self):
        co, old, jf, marker, binding, epoch, io = self.actual_binding(False)
        released = co.release_journal_handoff(old, binding, epoch, 3.0)
        reacquired = co.reacquire_journal(released, 3.0)
        self.assertEqual(7, len(co._inventory)); self.assertIsNone(co._tmp_alias)
        self.assertIs(old._device, reacquired.locks._device)

    def test_fixed_alias_full_initial_capacity_no_extra_open(self):
        co, io = self.coord(); co.acquire(); before = tuple(io.opened)
        with self.assertRaises(c.CoordinationError): co._open(None, None, 0)
        self.assertEqual(8, len(co._inventory)); self.assertEqual(before, tuple(io.opened))

    def test_wrong_first_link_rejects_before_prefix_open(self):
        co, io = self.coord(); io.nodes['/tmp'].data = b'/var/volatile/tmp'
        with self.assertRaises(c.CoordinationError): co.acquire()
        self.assertEqual(1, len(co._inventory)); self.assertFalse(io.handles)

    def test_wrong_second_link_retains_then_closes_original_prefix(self):
        co, io = self.coord(); io.nodes['/var/tmp'].data = b'/unexpected'
        with self.assertRaises(c.CoordinationError): co.acquire()
        self.assertEqual(2, len(co._inventory)); self.assertEqual(1, len(co._tmp_alias.prefix_tickets))
        self.assertFalse(io.handles); self.assertTrue(all(t.closed for t in co._inventory))

    def test_exact_root_uid_gid_and_directory_modes_not_general_sticky_allow(self):
        for path, field, value in (('/var', 'uid', 1), ('/var', 'gid', 1),
                ('/var', 'mode', stat.S_IFDIR | 0o1777),
                ('/var/volatile', 'mode', stat.S_IFDIR | 0o755),
                (a.PHYSICAL_TMP, 'mode', stat.S_IFDIR | 0o777),
                ('/tmp', 'links', 2), ('/var/tmp', 'mode', stat.S_IFLNK | 0o700)):
            with self.subTest(path=path, field=field):
                co, io = self.coord(); setattr(io.nodes[path], field, value)
                with self.assertRaises(c.CoordinationError): co.acquire()
                self.assertFalse(io.handles)

    def test_alias_change_after_acquire_blocks_before_new_flock(self):
        co, io = self.coord(); locks = co.acquire(); before = tuple(io.flocks)
        io.nodes['/var/tmp'].ino += 50
        with self.assertRaises(c.CoordinationError): co.validate(locks)
        self.assertEqual(before, tuple(io.flocks))
        io.nodes['/var/tmp'].ino -= 50
        with self.assertRaises(c.CoordinationError): co.validate(locks)  # Sticky observation failure.

    def test_physical_target_replacement_blocks_file_read(self):
        jf, io = self.files(); jf.open(); io.nodes[a.PHYSICAL_TMP].ino += 50
        with self.assertRaises(a.TmpAliasError): jf.read_current()
        self.assertFalse(any(op == 'read' for op, unused in io.ops))

    def test_var_entry_changed_not_same_fd_rejects(self):
        co, io = self.coord(); locks = co.acquire()
        io.add('/var', stat.S_IFDIR | 0o755)
        with self.assertRaises(c.CoordinationError): co.validate(locks)

    def test_root_entry_not_same_fd_rejects(self):
        co, io = self.coord(); locks = co.acquire()
        io.add('/', stat.S_IFDIR | 0o755)
        with self.assertRaises(c.CoordinationError): co.validate(locks)

    def test_directory_times_sizes_linkcount_change_are_not_identity(self):
        co, io = self.coord(); locks = co.acquire()
        for path in ('/', '/var', '/var/volatile', a.PHYSICAL_TMP):
            io.nodes[path].stamp += 10; io.nodes[path].links += 2; io.nodes[path].data = b'entry-size-change'
        self.assertTrue(co.validate(locks))

    def test_readlink_error_known_originals_close_once(self):
        co, io = self.coord(); io.faults[('readlink', '/var/tmp')] = OSError(errno.EACCES, 'HOST denied')
        with self.assertRaises(c.CoordinationError): co.acquire()
        self.assertFalse(io.handles); self.assertEqual(len(io.closed), len(set(io.closed)))

    def test_unknown_extra_open_retained_without_retry(self):
        co, io = self.coord(); io.unknown_path = '/var/volatile'
        with self.assertRaises(c.CoordinationError) as caught: co.acquire()
        self.assertEqual('io_error', caught.exception.code)  # Original _report wraps Exception, including MemoryError.
        self.assertEqual(3, len(co._inventory)); self.assertTrue(co._inventory[-1].opening_unknown)
        self.assertTrue(co.status()['resource_pending']); before = tuple(io.ops)
        co.close(); self.assertEqual(1, io.counts[('open', '/var/volatile')])
        self.assertFalse(io.handles); self.assertEqual(2, len(io.closed))

    def test_borrowed_extra_fd_unknown_not_closed_twice(self):
        co, io = self.coord(); io.borrow_path = '/var'
        with self.assertRaises(c.CoordinationError): co.acquire()
        self.assertEqual(co._inventory[0].fd, co._inventory[1].fd)
        self.assertTrue(co._inventory[1].opening_unknown)
        self.assertFalse(co._inventory[1].attempted)
        self.assertEqual([co._inventory[0].fd], io.closed)
        self.assertTrue(co.status()['resource_pending'])

    def test_late_extra_open_deadline_retains_returned_original(self):
        co, io = self.coord()
        def hook(io, op, path, count):
            if op == 'open' and path == '/var/volatile': io.clock.value += 10
        io.hook = hook
        with self.assertRaises(c.CoordinationError): co.acquire()
        self.assertEqual(3, len(co._inventory)); self.assertEqual(2, len(co._tmp_alias.prefix_tickets))
        self.assertTrue(all(t.closed for t in co._inventory)); self.assertFalse(io.handles)

    def test_close_error_extra_does_not_skip_device_last(self):
        co, io = self.coord(); locks = co.acquire()
        failed = co._tmp_alias.prefix_tickets[0]
        io.close_fail[failed.fd] = OSError(errno.EIO, 'HOST close unknown')
        result = co.close_device_last()
        self.assertEqual(locks._device.fd, io.closed[-1])
        self.assertTrue(result['resource_pending']); self.assertEqual(1, io.closed.count(failed.fd))
        co.close_device_last(); self.assertEqual(1, io.closed.count(failed.fd))

    def test_files_close_extra_failure_sticky_independent(self):
        jf, io = self.files(); jf.open(); failed = jf._tmp_alias.prefix_tickets[0]
        io.close_fail[failed.fd] = OSError(errno.EIO, 'HOST close unknown')
        result = jf.close()
        self.assertTrue(result['resource_pending']); self.assertFalse(result['all_owned_fds_closed'])
        self.assertEqual(6, len(io.closed)); jf.close(); self.assertEqual(6, len(io.closed))

    def test_foreign_context_and_repeat_prepare_bind_reject(self):
        co, io = self.coord(); co.acquire(); anchor = co._tmp_alias
        self.assertIs(anchor.authenticate(co, co._anchors[0][0]), anchor)
        with self.assertRaises(a.TmpAliasError): anchor.prepare()
        with self.assertRaises(a.TmpAliasError): anchor.bind_tmp(anchor.tmp_ticket)
        with self.assertRaises(a.TmpAliasError): anchor.authenticate(object(), co._anchors[0][0])
        with self.assertRaises(a.TmpAliasError): anchor.authenticate(co, co._anchors[0][0])
        self.assertNotIn('/var/', repr(anchor)); self.assertNotIn(TOKEN, repr(anchor))

    def test_any_pending_entry_blocks_alias_before_lock(self):
        for mode in (stat.S_IFREG | 0o600, stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o700):
            with self.subTest(mode=mode):
                co, io = self.coord(); node = io.add(PHYSICAL_PENDING, mode, b'unknown')
                with self.assertRaises(c.CoordinationError): co.acquire()
                self.assertFalse(io.flocks); self.assertIs(node, io.nodes[PHYSICAL_PENDING])

    def test_private_run_mode_remains_strict(self):
        jf, io = self.files(); io.nodes[PHYSICAL_RUN].mode = stat.S_IFDIR | 0o755
        with self.assertRaises(f.ClientFileError): jf.open()
        self.assertFalse(io.handles)


if __name__ == '__main__': unittest.main()
