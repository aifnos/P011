"""HOST FakeOS only: real file/flock/process/network calls are forbidden."""
import ast
import ctypes
import errno
import importlib.util
import os
import socket
import stat
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime')))
import mta_client_coordination as c
import mta_p2p_client_init as core


TOKEN = '1' * 32
IDENTITY = core.Identity('a' * 64)
BASE = '/tmp/' + c.BASE
RUN = BASE + '/client-' + TOKEN
DEVICE = '/tmp/' + c.DEVICE_LOCK
JOURNAL = RUN + '/' + c.JOURNAL_LOCK
PENDING = '/tmp/' + c.GLOBAL_PENDING


class Node(object):
    def __init__(self, path, mode, inode, uid=0, links=1, size=0):
        self.path, self.mode, self.inode = path, mode, inode
        self.uid, self.gid, self.links, self.size = uid, 0, links, size

    def metadata(self):
        return types.SimpleNamespace(st_dev=1, st_ino=self.inode, st_mode=self.mode,
            st_uid=self.uid, st_gid=self.gid, st_nlink=self.links, st_size=self.size)


class Clock(object):
    def __init__(self, value=1.0): self.value = value
    def __call__(self): return self.value


class FakeIo(object):
    FLAGS = {'O_RDONLY': 0, 'O_RDWR': 2, 'O_NONBLOCK': 2048, 'O_CREAT': 64,
        'O_EXCL': 128, 'O_DIRECTORY': 65536, 'O_NOFOLLOW': 131072, 'O_CLOEXEC': 524288}

    def __init__(self, clock=None):
        self.nodes, self.handles, self.ops, self.opened = {}, {}, [], []
        self.counter, self.next_inode = 10, 100
        self.hook, self.clock = None, clock or Clock()
        self.close_fail, self.keep_open, self.open_errors = {}, set(), {}
        self.flock_results, self.flock_error = {}, None
        self.closed, self.flocks, self.pauses = [], [], []
        for path, mode in (('/', 0o755), ('/tmp', 0o1777), (BASE, 0o700), (RUN, 0o700)):
            self.add(path, stat.S_IFDIR | mode)

    def add(self, path, mode=stat.S_IFREG | 0o600, uid=0, links=1, size=0):
        self.next_inode += 1
        value = Node(path, mode, self.next_inode, uid, links, size)
        self.nodes[path] = value
        return value

    def event(self, action, path):
        self.ops.append((action, path))
        if self.hook: self.hook(self, action, path)

    def validate(self): self.event('validate', 'fixed')
    def flag(self, name): return self.FLAGS[name]
    def path(self, parent, name): return self.handles[parent].path.rstrip('/') + '/' + name
    def open_root(self, flags): return self._open('/', flags, 0)
    def open_at(self, parent, name, flags, mode=0): return self._open(self.path(parent, name), flags, mode)

    def _open(self, path, flags, mode):
        self.event('open', path)
        self.opened.append((path, flags, mode))
        if path in self.open_errors: raise self.open_errors[path]
        if flags & self.FLAGS['O_CREAT']:
            if path in self.nodes and flags & self.FLAGS['O_EXCL']: raise OSError(errno.EEXIST, 'private exists')
            if path not in self.nodes: self.add(path, stat.S_IFREG | mode)
        if path not in self.nodes: raise OSError(errno.ENOENT, 'private absent')
        self.counter += 1
        self.handles[self.counter] = self.nodes[path]
        return self.counter

    def stat_at(self, parent, name):
        path = self.path(parent, name)
        self.event('stat', path)
        if path not in self.nodes: raise OSError(errno.ENOENT, 'private absent')
        return self.nodes[path].metadata()

    def fstat(self, fd):
        self.event('fstat', str(fd))
        if fd not in self.handles: raise OSError(errno.EBADF, 'private closed')
        return self.handles[fd].metadata()

    def flock(self, fd, flags):
        path = self.handles[fd].path
        self.event('flock', path)
        self.flocks.append((fd, flags))
        if self.flock_error: raise self.flock_error
        result = self.flock_results.get(path, (0, 0))
        if isinstance(result, list): return result.pop(0)
        return result

    def pause(self, seconds):
        self.pauses.append(seconds)
        self.clock.value += seconds

    def close(self, fd):
        self.event('close', str(fd))
        self.closed.append(fd)
        if fd in self.close_fail: raise self.close_fail[fd]
        if fd not in self.keep_open: self.handles.pop(fd, None)


class CoordinationTests(unittest.TestCase):
    def setUp(self):
        for name in ('open', 'read', 'write', 'close', 'stat', 'lstat', 'fstat',
                     'mkdir', 'unlink', 'replace', 'rename', 'kill', 'waitpid', 'fork', 'dup', 'fsync'):
            if hasattr(os, name):
                patcher = mock.patch.object(os, name, side_effect=AssertionError('actual OS forbidden'))
                patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket'):
            patcher = mock.patch(target, side_effect=AssertionError('actual native/network forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)

    def make(self, io=None, **kw):
        io = io or FakeIo()
        obj = c.ClientCoordination(TOKEN, IDENTITY, _io=io, _clock=io.clock, **kw)
        self.addCleanup(obj.close)
        return obj, io

    def acquired(self, io=None):
        obj, io = self.make(io)
        return obj, io, obj.acquire()

    def reject(self, action, code):
        with self.assertRaises(c.CoordinationError) as raised: action()
        self.assertEqual(code, raised.exception.code)
        for private in (TOKEN, RUN, 'private', '/usr/bin/'):
            self.assertNotIn(private, str(raised.exception))

    def test_constructor_and_import_pure(self):
        obj, io = self.make()
        self.assertEqual([], io.ops)
        spec = importlib.util.spec_from_file_location('host_coordination', c.__file__)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        module.ClientCoordination(TOKEN, IDENTITY, _io=io)
        self.assertEqual([], io.ops)
        self.assertFalse(obj.status()['mutation_admission'])

    def test_python35_ast_and_forbidden_operations(self):
        with open(c.__file__, encoding='utf-8') as source: tree = ast.parse(source.read(), feature_version=(3, 5))
        attrs = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertFalse({'fork', 'dup', 'kill', 'waitpid', 'mkdir', 'unlink', 'rename', 'socket', 'write'} & attrs)
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        self.assertFalse(any(isinstance(node, ast.Import) and any(x.name in ('json', 'fcntl', 'resource') for x in node.names)
                             for node in ast.walk(tree)))
        obj, _ = self.make()
        for name in ('finish', 'clear', 'commit', 'register_inherited', 'executor'):
            self.assertFalse(hasattr(obj, name))

    def test_config_exact_types_and_finite_budget(self):
        for token in ('', '1' * 31, 'A' * 32, '../' + '1' * 29, True):
            self.reject(lambda: c.ClientCoordination(token, IDENTITY), 'invalid_config')
        for budget in (True, 0, 11, float('nan'), float('inf'), 10 ** 1000):
            self.reject(lambda: c.ClientCoordination(TOKEN, IDENTITY, timeout=budget), 'invalid_config')
        self.reject(lambda: c.ClientCoordination(TOKEN, object()), 'invalid_config')

    def test_fixed_paths_and_exclusive_first_lock_creation(self):
        obj, io, locks = self.acquired()
        paths = [path for action, path in io.ops if action == 'open']
        self.assertEqual(['/', '/tmp', BASE, RUN, DEVICE, JOURNAL], paths)
        self.assertTrue(all(flags == 65536 | 131072 | 524288 and mode == 0 for _, flags, mode in io.opened[:4]))
        self.assertTrue(all(flags == 2 | 2048 | 131072 | 524288 | 64 | 128 and mode == 0o600
                            for _, flags, mode in io.opened[4:]))
        self.assertTrue(all(flags == 6 for _, flags in io.flocks))
        self.assertNotIn(PENDING, io.nodes)
        self.assertTrue(obj.validate(locks))
        self.assertFalse(obj.status()['same_ofd_verified'])

    def test_existing_locks_not_recreated(self):
        io = FakeIo(); device = io.add(DEVICE); journal = io.add(JOURNAL)
        obj, io, locks = self.acquired(io)
        self.assertEqual(device.inode, locks._device.identity[1])
        self.assertEqual(journal.inode, locks._journal.identity[1])
        self.assertTrue(all(flags == 2 | 2048 | 131072 | 524288 and mode == 0 for _, flags, mode in io.opened[4:]))
        self.assertEqual([], io.pauses)

    def test_no_missing_directory_creation(self):
        for path in (BASE, RUN):
            io = FakeIo(); del io.nodes[path]
            obj, _ = self.make(io)
            self.reject(obj.acquire, 'io_error')
            self.assertNotIn(DEVICE, io.nodes)
            self.assertTrue(obj.status()['all_original_fds_closed'])

    def test_directory_permissions_and_sticky_tmp(self):
        for path, mode in ((BASE, 0o755), (RUN, 0o777), ('/tmp', 0o777), ('/', 0o777)):
            io = FakeIo(); io.nodes[path].mode = stat.S_IFDIR | mode
            obj, _ = self.make(io)
            self.reject(obj.acquire, 'unsafe_directory')
            self.assertEqual([], io.flocks)

    def test_directory_swap_between_entry_and_fd(self):
        io = FakeIo()
        def hook(value, action, path):
            if action == 'open' and path == RUN: value.add(RUN, stat.S_IFDIR | 0o700)
        io.hook = hook
        obj, _ = self.make(io)
        self.reject(obj.acquire, 'directory_changed')
        self.assertTrue(obj.status()['all_original_fds_closed'])

    def test_any_global_pending_entry_blocks_before_lock_creation(self):
        for mode in (stat.S_IFREG | 0o600, stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o700, stat.S_IFIFO | 0o600):
            io = FakeIo(); pending = io.add(PENDING, mode)
            obj, _ = self.make(io)
            self.reject(obj.acquire, 'global_pending_blocked')
            self.assertIs(pending, io.nodes[PENDING])
            self.assertNotIn(DEVICE, io.nodes)
            self.assertEqual([], io.flocks)

    def test_pending_permission_and_noninteger_enoent_not_absence(self):
        for number in (errno.EACCES, float(errno.ENOENT), True):
            io = FakeIo()
            def hook(value, action, path, number=number):
                if action == 'stat' and path == PENDING: raise OSError(number, 'private denied')
            io.hook = hook
            obj, _ = self.make(io)
            self.reject(obj.acquire, 'io_error')
            self.assertEqual([], io.flocks)

    def test_pending_appears_after_device_before_journal(self):
        io = FakeIo()
        def hook(value, action, path):
            if action == 'flock' and path == DEVICE: value.add(PENDING)
        io.hook = hook
        obj, _ = self.make(io)
        self.reject(obj.acquire, 'global_pending_blocked')
        self.assertNotIn(JOURNAL, io.nodes)
        self.assertTrue(obj.status()['all_original_fds_closed'])

    def test_pending_last_gate_blocks_and_retains_entry(self):
        io = FakeIo()
        def hook(value, action, path):
            if action == 'flock' and path == JOURNAL: value.add(PENDING)
        io.hook = hook
        obj, _ = self.make(io)
        self.reject(obj.acquire, 'global_pending_blocked')
        self.assertIn(PENDING, io.nodes)
        self.assertTrue(obj.status()['all_original_fds_closed'])

    def test_unsafe_lock_type_owner_mode_links_size(self):
        changes = (('mode', stat.S_IFLNK | 0o600), ('mode', stat.S_IFIFO | 0o600),
                   ('mode', stat.S_IFREG | 0o666), ('uid', 1000), ('links', 2), ('size', 1))
        for attr, value in changes:
            io = FakeIo(); setattr(io.add(DEVICE), attr, value)
            obj, _ = self.make(io)
            self.reject(obj.acquire, 'unsafe_lock')
            self.assertEqual([], io.flocks)

    def test_existing_lock_inode_replaced_at_open_rejected(self):
        io = FakeIo(); io.add(DEVICE)
        def hook(value, action, path):
            if action == 'open' and path == DEVICE: value.add(DEVICE)
        io.hook = hook
        obj, _ = self.make(io)
        self.reject(obj.acquire, 'lock_changed')
        self.assertEqual([], io.flocks)

    def test_excl_race_does_not_fallback_or_retry_open(self):
        io = FakeIo()
        def hook(value, action, path):
            if action == 'open' and path == DEVICE: value.add(DEVICE)
        io.hook = hook
        obj, _ = self.make(io)
        self.reject(obj.acquire, 'lock_create_race')
        self.assertEqual(1, io.ops.count(('open', DEVICE)))
        self.assertFalse(obj.status()['resource_pending'])

    def test_known_eagain_and_eintr_only_budgeted_retries(self):
        io = FakeIo(); io.flock_results[DEVICE] = [(-1, errno.EAGAIN), (-1, errno.EINTR), (0, 0)]
        obj, io, _ = self.acquired(io)
        self.assertEqual(4, len(io.flocks))
        self.assertEqual([0.01, 0.01], io.pauses)
        self.assertFalse(obj.status()['lock_unknown'])

    def test_busy_lock_deadline_closes_known_resources(self):
        io = FakeIo(); io.flock_results[DEVICE] = (-1, errno.EAGAIN)
        obj, _ = self.make(io, timeout=0.1)
        self.reject(obj.acquire, 'deadline')
        self.assertLessEqual(len(io.pauses), 11)
        self.assertTrue(obj.status()['all_original_fds_closed'])
        self.assertFalse(obj.status()['lock_unknown'])

    def test_known_nonretry_flock_error(self):
        io = FakeIo(); io.flock_results[DEVICE] = (-1, errno.EPERM)
        obj, _ = self.make(io)
        self.reject(obj.acquire, 'flock_failed')
        self.assertEqual([], io.pauses)
        self.assertTrue(obj.status()['all_original_fds_closed'])

    def test_invalid_flock_result_sticky_unknown_no_retry(self):
        for result in ((True, 0), (0, True), (1, 0), (-1, 0), (-1, 4096), None):
            io = FakeIo(); io.flock_results[DEVICE] = result
            obj, _ = self.make(io)
            self.reject(obj.acquire, 'flock_unknown')
            self.assertEqual(1, len(io.flocks))
            self.assertTrue(obj.status()['lock_unknown'])
            self.assertTrue(obj.status()['resource_pending'])
            self.assertFalse(obj.read_closed().complete())

    def test_nonreturned_flock_exception_keeps_original_refs(self):
        io = FakeIo(); io.flock_error = MemoryError('private unknown')
        obj, _ = self.make(io)
        self.reject(obj.acquire, 'io_error')
        original = obj._inventory[-1]
        self.assertIs(io, original.io)
        self.assertTrue(original.attempted)
        self.assertTrue(obj.status()['lock_unknown'])
        before = list(io.flocks)
        obj.close(); obj.read_closed()
        self.assertEqual(before, io.flocks)

    def test_nonreturned_open_memoryerror_keeps_registered_unknown(self):
        io = FakeIo(); io.open_errors[DEVICE] = MemoryError('private unknown')
        obj, _ = self.make(io)
        self.reject(obj.acquire, 'io_error')
        self.assertEqual(1, obj.status()['unreturned_open_count'])
        self.assertTrue(obj.status()['resource_pending'])
        self.assertIs(io, obj._inventory[-1].io)
        self.assertFalse(obj.read_closed().complete())

    def test_open_allocates_then_nonreturns_no_guessed_close(self):
        io = FakeIo()
        def open_unknown(parent, name, flags, mode=0):
            fd = io._open(io.path(parent, name), flags, mode)
            if name == c.DEVICE_LOCK: raise MemoryError('private after allocation')
            return fd
        io.open_at = open_unknown
        obj, _ = self.make(io)
        self.reject(obj.acquire, 'io_error')
        self.assertEqual(1, len(io.handles))
        self.assertTrue(obj.status()['resource_pending'])
        self.assertFalse(obj.read_closed().complete())

    def test_invalid_returned_descriptor_not_closed_as_number(self):
        io = FakeIo(); original = io.open_at
        io.open_at = lambda parent, name, flags, mode=0: True if name == c.DEVICE_LOCK else original(parent, name, flags, mode)
        obj, _ = self.make(io)
        self.reject(obj.acquire, 'invalid_descriptor')
        self.assertEqual(1, obj.status()['unreturned_open_count'])
        self.assertNotIn(True, io.closed)

    def test_late_successful_flock_expiry_never_returns_lockset(self):
        io = FakeIo()
        def hook(value, action, path):
            if action == 'flock' and path == DEVICE: value.clock.value += 20
        io.hook = hook
        obj, _ = self.make(io)
        self.reject(obj.acquire, 'deadline')
        self.assertIsNone(obj._locks)
        self.assertTrue(obj.status()['all_original_fds_closed'])

    def test_clock_regression_and_free_exception_are_fixed(self):
        for clock in (iter((2.0, 1.0)).__next__, lambda: float('nan'), lambda: 10 ** 1000):
            io = FakeIo(); obj = c.ClientCoordination(TOKEN, IDENTITY, _io=io, _clock=clock)
            self.addCleanup(obj.close)
            with self.assertRaises(c.CoordinationError): obj.acquire()
        def bad_clock(): raise RuntimeError('private clock')
        obj = c.ClientCoordination(TOKEN, IDENTITY, _io=FakeIo(), _clock=bad_clock)
        self.reject(obj.acquire, 'invalid_clock')

    def test_validate_checks_actual_flock_and_changed_entry(self):
        obj, io, locks = self.acquired()
        count = len(io.flocks)
        self.assertTrue(obj.validate(locks))
        self.assertEqual(count + 2, len(io.flocks))
        io.add(DEVICE)
        self.reject(lambda: obj.validate(locks), 'lock_changed')

    def test_foreign_lockset_and_repeated_acquisition_rejected(self):
        obj, _, locks = self.acquired()
        other, _ = self.make()
        self.reject(lambda: other.validate(locks), 'invalid_lockset')
        forged = c.LockSet(obj._issuer, locks._device, locks._journal)
        self.reject(lambda: obj.validate(forged), 'invalid_lockset')
        self.reject(obj.acquire, 'already_attempted')

    def test_read_pending_only_absence_and_fresh_block(self):
        obj, io, locks = self.acquired()
        self.assertEqual({'entry_absent_observed': True, 'pending_modified': False, 'mutation_admission': False}, obj.read_pending(locks))
        io.add(PENDING)
        self.reject(lambda: obj.read_pending(locks), 'global_pending_blocked')
        self.assertIn(PENDING, io.nodes)

    def test_journal_release_keeps_device_and_no_unlock(self):
        obj, io, locks = self.acquired()
        obj.release_journal(locks)
        self.assertNotIn(locks._journal.fd, io.handles)
        self.assertIn(locks._device.fd, io.handles)
        self.assertEqual(1, len(io.closed))
        self.assertTrue(obj.read_pending(locks)['entry_absent_observed'])
        self.reject(lambda: obj.validate(locks), 'not_acquired')
        obj.close()
        self.assertEqual(6, len(set(io.closed)))
        self.assertTrue(all(flags == 6 for _, flags in io.flocks))

    def test_close_independently_attempts_every_original_once(self):
        obj, io, locks = self.acquired()
        io.close_fail[locks._journal.fd] = OSError(errno.EIO, 'private close')
        obj.close()
        self.assertEqual(6, len(set(io.closed)))
        self.assertTrue(obj.status()['resource_pending'])
        before = list(io.closed)
        obj.close(); obj.read_closed(locks)
        self.assertEqual(before, io.closed)

    def test_strict_ebadf_and_close_return_type(self):
        for number in (True, float(errno.EBADF), errno.EIO):
            obj, io, locks = self.acquired()
            fd = locks._journal.fd; original = io.fstat
            def readback(value, fd=fd, number=number):
                if value == fd and value not in io.handles: raise OSError(number, 'private unknown')
                return original(value)
            io.fstat = readback
            obj.close()
            self.assertTrue(obj.status()['resource_pending'])
            self.assertFalse(obj.read_closed(locks).complete())

    def test_close_consumed_but_raised_keeps_unknown(self):
        obj, io, locks = self.acquired()
        fd = locks._journal.fd; original = io.close
        def raised(value):
            original(value)
            if value == fd: raise OSError(errno.EINTR, 'private interrupted close')
        io.close = raised
        obj.close()
        self.assertTrue(obj.status()['resource_pending'])
        observation = obj.read_closed(locks)
        self.assertTrue(all(observation.observed))
        self.assertFalse(observation.complete())
        before = list(io.closed); obj.close()
        self.assertEqual(before, io.closed)

    def test_close_fd_reuse_never_recloses_replacement(self):
        obj, io, locks = self.acquired()
        fd = locks._journal.fd; original = io.close
        def replaced(value):
            original(value)
            if value == fd: io.handles[fd] = Node('/private/replacement', stat.S_IFREG | 0o600, 900)
        io.close = replaced
        obj.close()
        self.assertTrue(obj.status()['resource_pending'])
        self.assertFalse(obj.read_closed(locks).complete())
        before = list(io.closed); obj.close()
        self.assertEqual(before, io.closed)
        self.assertIn(fd, io.handles)

    def test_read_closed_never_opens_flocks_or_closes(self):
        obj, io, locks = self.acquired()
        obj.close(); before = list(io.ops)
        observation = obj.read_closed(locks)
        self.assertTrue(observation.complete())
        self.assertEqual(6, len(observation.observed))
        self.assertTrue(all(action == 'fstat' for action, _ in io.ops[len(before):]))
        self.assertFalse(obj.status()['store_implemented'])

    def test_unattempted_observation_is_not_zero_resource_proof(self):
        obj, _ = self.make()
        observation = obj.read_closed()
        self.assertFalse(observation.complete())
        self.assertEqual((), observation.observed)

    def test_public_status_and_reprs_do_not_publish_identity(self):
        obj, _, locks = self.acquired()
        public = str(obj.status()) + repr(locks) + repr(obj.read_closed())
        for value in (TOKEN, RUN, DEVICE, IDENTITY.candidate_sha): self.assertNotIn(value, public)
        for key in ('mutation_admission', 'same_ofd_verified', 'executor_verified', 'store_implemented', 'pending_modified'):
            self.assertIs(obj.status()[key], False)

    def test_fake_libc_exact_flock_and_openat_prototypes(self):
        class Native(object):
            def __init__(self, value): self.value, self.calls = value, []
            def __call__(self, *args): self.calls.append(args); return self.value
        library = types.SimpleNamespace(flock=Native(0), openat=Native(55))
        io = c._LinuxIo()
        with mock.patch('ctypes.CDLL', return_value=library) as load, mock.patch.object(os, 'supports_dir_fd', set()):
            self.assertEqual((0, 0), io.flock(44, 6))
            self.assertEqual(55, io.open_at(33, c.JOURNAL_LOCK, 2, 0o600))
        load.assert_called_once_with(None, use_errno=True)
        self.assertEqual((ctypes.c_int, ctypes.c_int), library.flock.argtypes)
        self.assertIs(ctypes.c_int, library.flock.restype)
        self.assertEqual((ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint), library.openat.argtypes)
        self.assertEqual([(44, 6)], library.flock.calls)
        self.assertEqual([(33, b'journal.lock', 2, 0o600)], library.openat.calls)


if __name__ == '__main__': unittest.main()
