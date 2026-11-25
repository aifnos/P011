"""HOST FakeFS only. No real /tmp, file locks, libc, WSL or device calls."""
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
import mta_client_files as f
import mta_client_journal_codec as codec
import mta_p2p_client_init as core
from test_client_journal_codec import record, IDENTITY


TOKEN = '1' * 32
BASE = '/tmp/' + f.ROOT_COMPONENT
RUN = BASE + '/client-' + TOKEN
TARGET = RUN + '/journal.json'
PENDING = '/tmp/' + f.GLOBAL_PENDING


class Node(object):
    def __init__(self, path, mode, ino, data=b'', uid=0, links=1):
        self.path, self.mode, self.ino, self.data = path, mode, ino, data
        self.uid, self.gid, self.links, self.stamp = uid, 0, links, 100

    def metadata(self):
        return types.SimpleNamespace(st_dev=1, st_ino=self.ino, st_mode=self.mode,
            st_uid=self.uid, st_gid=self.gid, st_nlink=self.links,
            st_size=len(self.data), st_mtime_ns=self.stamp, st_ctime_ns=self.stamp)


class FakeIo(object):
    FLAGS = {'O_RDONLY': 0, 'O_WRONLY': 1, 'O_CREAT': 64, 'O_EXCL': 128,
        'O_DIRECTORY': 65536, 'O_NOFOLLOW': 131072, 'O_CLOEXEC': 524288, 'O_NONBLOCK': 2048}

    def __init__(self):
        self.nodes = {}
        for path, mode in (('/', 0o755), ('/tmp', 0o1777), (BASE, 0o700), (RUN, 0o700)):
            self.add(path, stat.S_IFDIR | mode)
        self.fd, self.handles, self.opened, self.closed = 10, {}, [], []
        self.ops, self.counts, self.faults, self.hook = [], {}, {}, None
        self.close_fail, self.keep_open, self.read_result, self.write_result = {}, set(), None, None
        self.read_chunk, self.write_chunk = None, None
        self.validate_error = None
        self.unknown_open = None

    def add(self, path, mode=stat.S_IFREG | 0o600, data=b'', uid=0, links=1):
        node = Node(path, mode, len(self.nodes) + 100, data, uid, links)
        self.nodes[path] = node
        return node

    def flag(self, name): return self.FLAGS[name]

    def event(self, operation, path):
        self.ops.append((operation, path))
        key = operation, path
        self.counts[key] = self.counts.get(key, 0) + 1
        if self.hook: self.hook(self, operation, path, self.counts[key])
        if key in self.faults: raise self.faults[key]

    def validate(self):
        if self.validate_error: raise self.validate_error

    def path(self, parent, name):
        node = self.handles[parent][0]
        return node.path.rstrip('/') + '/' + name

    def open_root(self, flags): return self._open('/', flags, 0)
    def open_at(self, parent, name, flags, mode=0): return self._open(self.path(parent, name), flags, mode)

    def _open(self, path, flags, mode):
        self.event('open', path)
        if self.unknown_open: raise self.unknown_open
        if flags & self.FLAGS['O_CREAT']:
            if path in self.nodes and flags & self.FLAGS['O_EXCL']: raise OSError(errno.EEXIST, 'HOST exists')
            if path not in self.nodes: self.add(path, stat.S_IFREG | mode)
        if path not in self.nodes: raise OSError(errno.ENOENT, 'HOST absent')
        self.fd += 1
        self.handles[self.fd] = [self.nodes[path], 0]
        self.opened.append((path, flags, mode, self.fd))
        return self.fd

    def stat_at(self, parent, name):
        path = self.path(parent, name)
        self.event('stat', path)
        if path not in self.nodes: raise OSError(errno.ENOENT, 'HOST absent')
        return self.nodes[path].metadata()

    def fstat(self, fd):
        if fd not in self.handles: raise OSError(errno.EBADF, 'HOST closed')
        node = self.handles[fd][0]
        self.event('fstat', node.path)
        return node.metadata()

    def read(self, fd, count):
        node, at = self.handles[fd]
        self.event('read', node.path)
        if self.read_result is not None: return self.read_result
        count = min(count, self.read_chunk) if self.read_chunk else count
        data = node.data[at:at + count]
        self.handles[fd][1] += len(data)
        return data

    def write(self, fd, data):
        node, at = self.handles[fd]
        self.event('write', node.path)
        if self.write_result is not None: return self.write_result
        amount = min(len(data), self.write_chunk) if self.write_chunk else len(data)
        node.data = node.data[:at] + data[:amount] + node.data[at + amount:]
        node.stamp += 1
        self.handles[fd][1] += amount
        return amount

    def fsync(self, fd): self.event('fsync', self.handles[fd][0].path)

    def rename_at(self, parent, source, target):
        path, destination = self.path(parent, source), self.path(parent, target)
        self.event('rename', path)
        node = self.nodes.pop(path)
        node.path = destination
        self.nodes[destination] = node

    def close(self, fd):
        self.closed.append(fd)
        if fd in self.close_fail: raise self.close_fail[fd]
        if fd not in self.keep_open: del self.handles[fd]


class FilesTests(unittest.TestCase):
    def setUp(self):
        for name in ('open', 'read', 'write', 'close', 'fsync', 'stat', 'lstat',
                     'fstat', 'replace', 'rename', 'unlink', 'mkdir', 'kill', 'waitpid'):
            patcher = mock.patch.object(os, name, side_effect=AssertionError('actual OS forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket'):
            patcher = mock.patch(target, side_effect=AssertionError('actual native/network forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)

    def make(self, io=None, **kwargs):
        io = io or FakeIo()
        obj = f.ClientJournalFiles(TOKEN, IDENTITY, _io=io, _clock=lambda: 1.0, **kwargs)
        return obj, io

    def opened(self, io=None):
        obj, io = self.make(io)
        obj.open()
        self.addCleanup(obj.close)
        return obj, io

    def reject(self, action, code):
        with self.assertRaises(f.ClientFileError) as caught: action()
        self.assertEqual(code, caught.exception.code)
        for value in (TOKEN, RUN, 'private text', '/usr/bin/'):
            self.assertNotIn(value, str(caught.exception))

    def test_constructor_import_pure(self):
        obj, io = self.make()
        self.assertEqual([], io.ops)
        spec = importlib.util.spec_from_file_location('host_client_files', f.__file__)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        module.ClientJournalFiles(TOKEN, IDENTITY, _io=io)
        self.assertEqual([], io.ops)
        self.assertFalse(obj.status()['mutation_admission'])

    def test_python35_ast_no_forbidden_ops_or_ui_path(self):
        with open(f.__file__, encoding='utf-8') as source: tree = ast.parse(source.read(), feature_version=(3, 5))
        attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertFalse({'flock', 'kill', 'waitpid', 'fork', 'socket', 'mkdir', 'unlink', 'rmdir'} & attrs)
        obj, _ = self.make()
        for name in ('finish', 'clear', 'closed_locks', 'read_path', 'acquire'):
            self.assertFalse(hasattr(obj, name))

    def test_fixed_tokens_budgets_identity_no_io(self):
        for token in ('', '1' * 31, 'A' * 32, '../' + '1' * 29, True):
            self.reject(lambda: f.ClientJournalFiles(token, IDENTITY), 'invalid_config')
        for budget in (True, 0, 11, float('nan'), 10 ** 1000):
            self.reject(lambda: f.ClientJournalFiles(TOKEN, IDENTITY, timeout=budget), 'invalid_config')
        self.reject(lambda: f.ClientJournalFiles(TOKEN, object()), 'invalid_config')

    def test_open_existing_fixed_chain_flags_and_no_creation(self):
        obj, io = self.opened()
        self.assertEqual(['/', '/tmp', BASE, RUN], [r[0] for r in io.opened])
        self.assertTrue(all(r[1] == 65536 | 131072 | 524288 and r[2] == 0 for r in io.opened))
        self.assertEqual(None, obj.read_current())
        self.assertNotIn(TARGET, io.nodes)
        obj.close()
        self.assertTrue(obj.status()['all_owned_fds_closed'])
        self.assertEqual(4, len(io.closed))

    def test_missing_directories_never_mkdir_and_close_all(self):
        for path in (BASE, RUN):
            io = FakeIo(); del io.nodes[path]
            obj, _ = self.make(io)
            self.reject(obj.open, 'io_error')
            self.assertFalse(io.handles)
            self.assertTrue(obj.status()['all_owned_fds_closed'])

    def test_ancestors_root_owned_and_tmp_sticky_private_leaf_modes(self):
        for path, attr, value in (('/', 'uid', 1), ('/tmp', 'mode', stat.S_IFDIR | 0o777),
                (BASE, 'mode', stat.S_IFDIR | 0o755), (RUN, 'mode', stat.S_IFDIR | 0o1700),
                (RUN, 'uid', 1), (BASE, 'mode', stat.S_IFLNK | 0o700)):
            io = FakeIo(); setattr(io.nodes[path], attr, value)
            obj, _ = self.make(io); self.reject(obj.open, 'unsafe_directory')
            self.assertFalse(io.handles)
        io = FakeIo(); io.nodes['/tmp'].mode = stat.S_IFDIR | 0o700
        self.opened(io)

    def test_directory_entry_replacement_and_live_mode_change(self):
        obj, io = self.opened()
        old = io.nodes[RUN]
        io.nodes[RUN] = Node(RUN, old.mode, old.ino + 100)
        self.reject(obj.read_current, 'directory_changed')
        io.nodes[RUN] = old; old.mode = stat.S_IFDIR | 0o755
        self.reject(obj.read_current, 'unsafe_directory')

    def test_global_pending_any_version_or_symlink_blocks_readonly(self):
        for mode in (stat.S_IFREG | 0o600, stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o700):
            io = FakeIo(); node = io.add(PENDING, mode, b'private old v3 pending')
            obj, _ = self.make(io); self.reject(obj.open, 'global_pending_blocked')
            self.assertIs(io.nodes[PENDING], node)
            self.assertEqual(b'private old v3 pending', node.data)
            self.assertFalse(any(op in ('write', 'rename', 'fsync') for op, _ in io.ops))
            self.assertFalse(io.handles)

    def test_global_pending_permission_or_float_enoent_not_absence(self):
        for error in (OSError(errno.EACCES, 'private text'), OSError(errno.EIO, 'private text')):
            io = FakeIo(); io.faults[('stat', PENDING)] = error
            obj, _ = self.make(io); self.reject(obj.open, 'io_error')
        io = FakeIo(); error = OSError(errno.ENOENT, 'private text'); error.errno = 2.0
        io.faults[('stat', PENDING)] = error
        obj, _ = self.make(io); self.reject(obj.open, 'io_error')

    def test_existing_global_pending_added_before_commit_no_new_file(self):
        obj, io = self.opened(); io.add(PENDING, data=b'old')
        self.reject(lambda: obj.commit(None, record('prepared')), 'global_pending_blocked')
        self.assertNotIn(TARGET, io.nodes)
        self.assertFalse(any('/journal.' in path for op, path in io.ops if op == 'open'))

    def test_read_exact_canonical_private_bytes_metadata(self):
        data = codec.encode_journal(record('prepared'))
        io = FakeIo(); io.add(TARGET, data=data)
        obj, io = self.opened(io); result = obj.read_current()
        self.assertIs(type(result), f.CanonicalRecord)
        self.assertEqual(data, result.data)
        self.assertEqual(record('prepared').key(), result.journal.key())
        self.assertNotIn('/usr/bin/', repr(result))
        with self.assertRaises(AttributeError): result.data = b'fake'
        flags = [r[1] for r in io.opened if r[0] == TARGET][0]
        self.assertTrue(flags & io.flag('O_NONBLOCK'))

    def test_nonregular_wrong_owner_mode_or_hardlinks_never_read(self):
        for mode, uid, links in ((stat.S_IFIFO | 0o600, 0, 1), (stat.S_IFLNK | 0o600, 0, 1),
                (stat.S_IFREG | 0o666, 0, 1), (stat.S_IFREG | 0o600, 1, 1),
                (stat.S_IFREG | 0o600, 0, 2)):
            io = FakeIo(); io.add(TARGET, mode, b'private', uid, links)
            obj, _ = self.opened(io); self.reject(obj.read_current, 'unsafe_file')
            self.assertFalse(any(op == 'read' for op, path in io.ops if path == TARGET))

    def test_invalid_schema_other_identity_and_noncanonical_rejected(self):
        for data in (b'{}', codec.encode_journal(record('prepared')) + b'\n'):
            io = FakeIo(); io.add(TARGET, data=data)
            obj, _ = self.opened(io); self.reject(obj.read_current, 'io_error')
        other = record('prepared').replace(identity=core.Identity('b' * 64))
        io = FakeIo(); io.add(TARGET, data=codec.encode_journal(other))
        obj, _ = self.opened(io); self.reject(obj.read_current, 'invalid_record')

    def test_read_chunk_and_byte_budget_fstat_changed(self):
        io = FakeIo(); io.add(TARGET, data=codec.encode_journal(record('prepared'))); io.read_chunk = 7
        obj, _ = self.opened(io); self.assertEqual(io.nodes[TARGET].data, obj.read_current().data)
        io.nodes[TARGET].data = b'x' * (codec.MAX_BYTES + 1)
        self.reject(obj.read_current, 'unsafe_file')
        io.nodes[TARGET].data = codec.encode_journal(record('prepared'))
        io.read_result = 'wrong bytes'; self.reject(obj.read_current, 'invalid_read')
        io.read_result = None
        def change(io, op, path, count):
            if op == 'read' and path == TARGET: io.nodes[path].stamp += 1
        io.hook = change; self.reject(obj.read_current, 'file_changed')

    def test_first_commit_order_full_bytes_and_actual_readback(self):
        obj, io = self.opened(); value = record('prepared')
        result = obj.commit(None, value)
        self.assertEqual(codec.encode_journal(value), io.nodes[TARGET].data)
        self.assertEqual(result.data, io.nodes[TARGET].data)
        temporary = RUN + '/journal.00000001.tmp'
        self.assertNotIn(temporary, io.nodes)
        fsync_file = io.ops.index(('fsync', temporary))
        rename = io.ops.index(('rename', temporary))
        fsync_directory = io.ops.index(('fsync', RUN))
        self.assertLess(fsync_file, rename); self.assertLess(rename, fsync_directory)
        self.assertTrue(any(op == 'read' and path == TARGET for op, path in io.ops[fsync_directory:]))
        self.assertFalse(obj.status()['write_pending'])

    def test_short_writes_read_chunks_full_and_update_receipt_generation(self):
        obj, io = self.opened(); io.write_chunk, io.read_chunk = 3, 5
        first = obj.commit(None, record('prepared'))
        second_value = record('prepared').replace(deadline=31.25)
        second = obj.commit(first, second_value)
        self.assertEqual(codec.encode_journal(second_value), second.data)
        self.reject(lambda: obj.commit(first, second_value), 'invalid_expected')

    def test_expected_none_cannot_overwrite_existing(self):
        io = FakeIo(); data = codec.encode_journal(record('prepared')); io.add(TARGET, data=data)
        obj, _ = self.opened(io)
        self.reject(lambda: obj.commit(None, record('prepared')), 'stale_current')
        self.assertEqual(data, io.nodes[TARGET].data)
        self.assertFalse(obj.status()['write_pending'])

    def test_receipt_from_other_instance_or_wrong_type_rejected(self):
        first, io = self.opened(); receipt = first.commit(None, record('prepared'))
        second, _ = self.opened(io)
        self.reject(lambda: second.commit(receipt, record('prepared')), 'invalid_expected')
        self.reject(lambda: first.commit(True, record('prepared')), 'invalid_expected')
        self.reject(lambda: first.commit(receipt, object()), 'invalid_record')

    def test_full_bytes_cas_even_if_core_key_unchanged(self):
        value = record(); io = FakeIo(); io.add(TARGET, data=codec.encode_journal(value))
        obj, _ = self.opened(io); receipt = obj.read_current()
        actor = value.controller
        changed = core.Actor(actor.pid, actor.start, actor.exe, actor.argv_sha,
            tuple((pid, start, 'R' if state == 'S' else state) for pid, start, state in actor.tasks))
        changed_value = value.replace(controller=changed)
        self.assertEqual(value.key(), changed_value.key())
        io.nodes[TARGET].data = codec.encode_journal(changed_value)
        self.reject(lambda: obj.commit(receipt, value), 'stale_current')

    def test_metadata_cas_even_same_bytes_replaced_inode(self):
        obj, io = self.opened(); receipt = obj.commit(None, record('prepared'))
        io.nodes[TARGET].ino += 1000
        self.reject(lambda: obj.commit(receipt, record('prepared')), 'stale_current')

    def test_second_fresh_cas_prevents_callback_overwrite(self):
        obj, io = self.opened(); receipt = obj.commit(None, record('prepared'))
        other = codec.encode_journal(record('prepared').replace(deadline=35.5))
        def change(io, op, path, count):
            if op == 'fsync' and path.endswith('00000002.tmp'):
                io.nodes[TARGET].data = other; io.nodes[TARGET].stamp += 1
        io.hook = change
        self.reject(lambda: obj.commit(receipt, record('prepared')), 'stale_current')
        self.assertEqual(other, io.nodes[TARGET].data)
        self.assertTrue(obj.status()['write_pending'])
        self.assertIn(RUN + '/journal.00000002.tmp', io.nodes)

    def test_temp_exists_exclusive_no_delete_or_retry(self):
        obj, io = self.opened(); temporary = RUN + '/journal.00000001.tmp'
        io.add(temporary, data=b'user existing')
        self.reject(lambda: obj.commit(None, record('prepared')), 'temp_exists')
        self.assertEqual(b'user existing', io.nodes[temporary].data)
        self.reject(lambda: obj.commit(None, record('prepared')), 'write_pending')

    def test_invalid_zero_bool_large_write_preserves_temp_and_no_rename(self):
        for value in (0, True, 5000, 'bad'):
            obj, io = self.opened(); io.write_result = value
            self.reject(lambda: obj.commit(None, record('prepared')), 'invalid_write')
            self.assertTrue(obj.status()['write_pending'])
            self.assertFalse(any(op == 'rename' for op, path in io.ops))

    def test_fsync_file_and_directory_einval_ebadf_are_not_swallowed(self):
        for stage in (RUN + '/journal.00000001.tmp', RUN):
            for error in (errno.EINVAL, errno.EBADF, errno.EIO):
                obj, io = self.opened(); io.faults[('fsync', stage)] = OSError(error, 'private text')
                self.reject(lambda: obj.commit(None, record('prepared')), 'durability_unknown')
                self.assertTrue(obj.status()['write_pending'])
                if stage == RUN: self.assertIn(TARGET, io.nodes)
                else: self.assertNotIn(TARGET, io.nodes)

    def test_global_pending_appears_after_write_blocks_rename(self):
        obj, io = self.opened()
        def appeared(io, op, path, count):
            if op == 'fsync' and path.endswith('.tmp'): io.add(PENDING, data=b'old pending')
        io.hook = appeared
        self.reject(lambda: obj.commit(None, record('prepared')), 'global_pending_blocked')
        self.assertNotIn(TARGET, io.nodes); self.assertIn(PENDING, io.nodes)

    def test_readback_different_after_rename_no_false_success(self):
        obj, io = self.opened()
        def changed(io, op, path, count):
            if op == 'fsync' and path == RUN:
                io.nodes[TARGET].data = codec.encode_journal(record('prepared').replace(deadline=50.5))
        io.hook = changed
        self.reject(lambda: obj.commit(None, record('prepared')), 'readback_changed')
        self.assertTrue(obj.status()['write_pending'])

    def test_same_bytes_replaced_inode_after_rename_preserves_unknown(self):
        obj, io = self.opened()
        def changed(io, op, path, count):
            if op == 'fsync' and path == RUN:
                original = io.nodes[TARGET]
                replacement = io.add(TARGET, data=original.data)
                replacement.ino = original.ino + 1000
        io.hook = changed
        self.reject(lambda: obj.commit(None, record('prepared')), 'readback_changed')
        status = obj.status()
        self.assertTrue(status['write_pending']); self.assertTrue(status['published_unknown'])
        self.assertTrue(obj._inventory[-1].closed)
        self.assertEqual(0, obj._generation)
        self.reject(lambda: obj.commit(None, record('prepared')), 'write_pending')
        obj.close()
        self.assertFalse(io.handles)
        self.assertIn(TARGET, io.nodes)
        self.assertTrue(obj.status()['published_unknown'])

    def test_same_bytes_same_inode_different_device_after_rename_rejected(self):
        obj, io = self.opened()
        def changed(io, op, path, count):
            if op == 'fsync' and path == RUN:
                node = io.nodes[TARGET]
                original_metadata = node.metadata
                def metadata():
                    value = original_metadata(); value.st_dev += 1
                    return value
                node.metadata = metadata
        io.hook = changed
        self.reject(lambda: obj.commit(None, record('prepared')), 'readback_changed')
        self.assertTrue(obj.status()['published_unknown'])
        self.assertEqual(0, obj._generation)

    def test_rename_time_change_same_stable_file_identity_is_allowed(self):
        obj, io = self.opened()
        observed = {}
        def changed(io, op, path, count):
            if op == 'fsync' and path.endswith('.tmp'):
                observed['written'] = io.nodes[path].metadata()
            if op == 'fsync' and path == RUN:
                io.nodes[TARGET].stamp += 1
        io.hook = changed
        result = obj.commit(None, record('prepared'))
        self.assertEqual(observed['written'].st_ino, result.metadata[1])
        self.assertNotEqual(observed['written'].st_ctime_ns, result.metadata[8])
        self.assertEqual(codec.encode_journal(record('prepared')), result.data)
        self.assertFalse(obj.status()['published_unknown'])

    def test_temp_fstat_identity_replaced_no_rename(self):
        obj, io = self.opened()
        def changed(io, op, path, count):
            if op == 'fsync' and path.endswith('.tmp'): io.nodes[path].ino += 1000
        io.hook = changed
        self.reject(lambda: obj.commit(None, record('prepared')), 'file_changed')
        self.assertNotIn(TARGET, io.nodes)

    def test_close_independent_unknown_exact_refs_no_repeat(self):
        obj, io = self.opened(); first_fd = io.opened[-1][3]
        io.close_fail[first_fd] = KeyboardInterrupt()
        status = obj.close()
        self.assertEqual(4, len(io.closed)); self.assertEqual(4, len(set(io.closed)))
        self.assertTrue(status['resource_pending']); self.assertFalse(status['all_owned_fds_closed'])
        self.assertIs(obj._inventory[-1].io, io)
        self.assertEqual(first_fd, obj._inventory[-1].fd)
        obj.close(); self.assertEqual(4, len(io.closed))
        self.reject(obj.read_current, 'resource_pending')

    def test_close_return_without_ebadf_blocks_and_attempts_all(self):
        obj, io = self.opened(); io.keep_open.add(io.opened[-1][3])
        self.assertTrue(obj.close()['resource_pending']); self.assertEqual(4, len(io.closed))

    def test_read_failure_and_memory_error_close_file_before_rethrow(self):
        for error in (OSError(errno.EIO, 'private text'), MemoryError(), KeyboardInterrupt()):
            io = FakeIo(); io.add(TARGET, data=codec.encode_journal(record('prepared')))
            obj, _ = self.opened(io); io.faults[('read', TARGET)] = error
            if isinstance(error, Exception): self.reject(obj.read_current, 'io_error')
            else:
                with self.assertRaises(KeyboardInterrupt): obj.read_current()
            self.assertEqual(1, len(io.closed))
            self.assertEqual(4, len(io.handles))

    def test_open_unexpected_exception_unknown_ticket_no_claim_closed(self):
        obj, io = self.make(); io.unknown_open = MemoryError()
        self.reject(obj.open, 'io_error')
        status = obj.status()
        self.assertTrue(status['resource_pending']); self.assertEqual(1, status['unresolved_open_count'])
        self.assertFalse(status['all_owned_fds_closed']); self.assertEqual([], io.closed)
        self.assertIs(obj._inventory[0].io, io)

    def test_temp_interrupted_still_close_all_and_preserve_original_exception(self):
        obj, io = self.opened()
        io.faults[('write', RUN + '/journal.00000001.tmp')] = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): obj.commit(None, record('prepared'))
        self.assertEqual(1, len(io.closed)); self.assertTrue(obj.status()['write_pending'])
        obj.close(); self.assertEqual(5, len(io.closed)); self.assertFalse(io.handles)

    def test_expired_and_regressed_clock_fail_no_new_resource(self):
        for values, code in (((1.0, 20.0), 'deadline'), ((1.0, .5), 'clock_regressed')):
            ticks = iter(values)
            obj = f.ClientJournalFiles(TOKEN, IDENTITY, _io=FakeIo(), _clock=lambda: next(ticks))
            self.reject(obj.open, code)
        for clock in (lambda: float('nan'), lambda: 10 ** 1000):
            obj = f.ClientJournalFiles(TOKEN, IDENTITY, _io=FakeIo(), _clock=clock)
            self.reject(obj.open, 'invalid_clock')

    def test_resource_budget_known_closed_not_dropped(self):
        obj, io = self.opened()
        io.add(TARGET, data=codec.encode_journal(record('prepared')))
        with mock.patch.object(f, 'MAX_RESOURCES', 5):
            obj.read_current()
            self.reject(obj.read_current, 'resource_budget')
        self.assertEqual(5, len(obj._inventory))

    def test_public_no_private_paths_hashes_or_authority(self):
        obj, _ = self.opened(); obj.commit(None, record('prepared'))
        status = obj.close()
        for private in (TOKEN, RUN, IDENTITY.candidate_sha, 'argv_sha', '/usr/bin/'):
            self.assertNotIn(private, repr(status))
        for key in ('global_pending_modified', 'store_finish_implemented', 'mutation_admission'):
            self.assertIs(status[key], False)

    def test_linux_adapter_typed_openat_and_renameat_fake_libc(self):
        class Function(object):
            def __init__(self, result): self.result, self.calls = result, []
            def __call__(self, *args): self.calls.append(args); return self.result
        library = types.SimpleNamespace(openat=Function(41), renameat=Function(0))
        adapter = f._LinuxIo()
        with mock.patch.object(f.ctypes, 'CDLL', return_value=library) as load, \
                mock.patch.object(f.os, 'supports_dir_fd', set()):
            self.assertEqual(41, adapter.open_at(8, 'journal.json', 1, 0o600))
            adapter.rename_at(8, 'journal.00000001.tmp', 'journal.json')
            load.assert_called_once_with(None, use_errno=True)
        self.assertEqual((ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint), library.openat.argtypes)
        self.assertEqual(ctypes.c_int, library.openat.restype)
        self.assertEqual((8, b'journal.json', 1, 0o600), library.openat.calls[0])
        self.assertEqual((8, b'journal.00000001.tmp', 8, b'journal.json'), library.renameat.calls[0])

    def test_close_never_clears_existing_global_pending(self):
        obj, io = self.opened(); node = io.add(PENDING, data=b'old')
        obj.close(); self.assertIs(node, io.nodes[PENDING]); self.assertEqual(b'old', node.data)


if __name__ == '__main__': unittest.main()
