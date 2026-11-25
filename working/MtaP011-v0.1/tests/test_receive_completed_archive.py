"""One NEW HOST MODEL method for the fixed future-run administrative IO.

Executes the complete fixed archive module's archive/open/FD/lock/journal/CAS/
rename/readback/fsync/close methods. Only _capture and _check_originals are
explicit Owner/Factory/Parent/State models: this test does NOT authenticate the
production closure consumer, an actual FinishReceipt, Native, Session finalizer,
ARM syscall, Linux OFD, P011 resource closure or restoration. No old test runs.
All target OS/libc/clock/codec references are isolated proxies, never shared
global module patches. There is no host filesystem mutation outside this file's
fixed source reads. The production module receives no ModelIO entry point.
"""
import ctypes
import errno
import hashlib
from pathlib import Path
import stat
import sys
import threading
import types
import unittest


BASE = Path(__file__).resolve().parents[1]
ARCHIVE_SOURCE = 'candidate/receive-completed-archive-v1/runtime/mta_receive_completed_archive.py'
OWNER_SOURCE = 'candidate/receive-completed-archive-v1/runtime/mta_client_service_owner.py'
PINS = {
    ARCHIVE_SOURCE: (41932, 'fef9d58f9d8359e8407500c9d461a1842e52f6e90cf2d670c2c0088a92d888ca'),
    OWNER_SOURCE: (80798, 'f9ef01ed2ecf95b13bba3627e7e810e097f75ed30e8ef470b51a2353fd874bab'),
}


class _Clock(object):
    def __init__(self): self.value = 1.0
    def monotonic(self): return self.value


class _Node(object):
    def __init__(self, inode, mode, data=b'', target=None):
        self.inode, self.mode, self.data, self.target = inode, mode, data, target
        self.children = {}
    def metadata(self):
        isdir = stat.S_ISDIR(self.mode)
        size = 4096 if isdir else len(self.target) if self.target is not None else len(self.data)
        return types.SimpleNamespace(st_dev=7, st_ino=self.inode, st_mode=self.mode,
            st_uid=0, st_gid=0, st_nlink=2 if isdir else 1, st_size=size)


class _ModelOS(object):
    O_RDONLY, O_RDWR = 0, 2
    O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC, O_NONBLOCK = 0x4000, 0x8000, 0x80000, 0x800
    def __init__(self, clock):
        self.clock, self.next_inode, self.next_fd = clock, 1, 101
        self.fd_nodes, self.offsets, self.opened, self.close_calls = {}, {}, [], []
        self.fsync_calls, self.mkdir_calls, self.stat_calls, self.open_calls = [], [], [], []
        self.pre_stat_failure = self.open_failure = self.fail_first_fstat = False
        self.fstat_failed = False
        self.close_fail_node, self.close_error = None, OSError(errno.EIO, 'MODEL_CLOSE')
        self.fsync_fail_on = self.expire_after_open = self.mutate_read_on = None
        self.read_number = 0
        self.root = self.node(stat.S_IFDIR | 0o755)
        var = self.child(self.root, 'var', stat.S_IFDIR | 0o755)
        volatile = self.child(var, 'volatile', stat.S_IFDIR | 0o1777)
        self.tmp = self.child(volatile, 'tmp', stat.S_IFDIR | 0o1777)
        self.client = self.child(self.tmp, 'p011-mta-client-rfinit', stat.S_IFDIR | 0o700)
        self.token = 'a' * 32
        self.run_name = 'client-' + self.token
        self.run = self.child(self.client, self.run_name, stat.S_IFDIR | 0o700)
        self.journal_raw = b'MODEL_TERMINAL_JOURNAL_DATA_ONLY_01'
        self.journal = self.child(self.run, 'journal.json', stat.S_IFREG | 0o600, self.journal_raw)
        self.journal_lock = self.child(self.run, 'journal.lock', stat.S_IFREG | 0o600)
        self.device_lock = self.child(self.tmp, 'p011-mta-p2p-device.lock', stat.S_IFREG | 0o600)
        self.history = self.child(self.client, 'old-history-model-do-not-read', stat.S_IFDIR | 0o700)
        self.history.children['preserve'] = self.node(stat.S_IFREG | 0o600, b'OLD_MODEL_BYTES')
        self.links = {'/tmp': self.node(stat.S_IFLNK | 0o777, target='/var/tmp'),
            '/var/tmp': self.node(stat.S_IFLNK | 0o777, target='/var/volatile/tmp')}
    def node(self, mode, data=b'', target=None):
        value = _Node(self.next_inode, mode, data, target)
        self.next_inode += 1
        return value
    def child(self, parent, name, mode, data=b''):
        value = self.node(mode, data)
        parent.children[name] = value
        return value
    def _node_at(self, name, dir_fd=None):
        if name == '/' and dir_fd is None: return self.root
        if type(dir_fd) is not int or dir_fd not in self.fd_nodes: raise OSError(errno.EBADF, 'MODEL_FD')
        parent = self.fd_nodes[dir_fd]
        if name not in parent.children: raise OSError(errno.ENOENT, 'MODEL_ABSENT')
        return parent.children[name]
    def stat(self, name, dir_fd=None, follow_symlinks=True):
        if follow_symlinks is not False: raise AssertionError('NOFOLLOW_REQUIRED')
        self.stat_calls.append(name)
        if self.pre_stat_failure and name == 'var':
            self.pre_stat_failure = False
            raise OSError(errno.EACCES, 'MODEL_PREOPEN')
        return self._node_at(name, dir_fd).metadata()
    def lstat(self, name):
        if name not in self.links: raise AssertionError('FIXED_ALIAS_ONLY')
        return self.links[name].metadata()
    def readlink(self, name): return self.links[name].target
    def open(self, name, flags, dir_fd=None):
        if flags & (self.O_NOFOLLOW | self.O_CLOEXEC) != self.O_NOFOLLOW | self.O_CLOEXEC:
            raise AssertionError('ORIGINAL_SAFE_FLAGS')
        if flags & 0x40: raise AssertionError('NO_CREATE')
        self.open_calls.append(name)
        if self.open_failure and name == 'var':
            self.open_failure = False
            raise OSError(errno.EACCES, 'MODEL_OPEN')
        value = self._node_at(name, dir_fd)
        fd = self.next_fd; self.next_fd += 1
        self.fd_nodes[fd], self.offsets[fd] = value, 0
        self.opened.append((fd, value))
        if self.expire_after_open == len(self.opened): self.clock.value = 8.0
        return fd
    def fstat(self, fd):
        if fd not in self.fd_nodes: raise OSError(errno.EBADF, 'MODEL_CLOSED')
        if self.fail_first_fstat and not self.fstat_failed:
            self.fstat_failed = True
            raise OSError(errno.EIO, 'MODEL_RETURNED_FD_UNKNOWN')
        return self.fd_nodes[fd].metadata()
    def close(self, fd):
        self.close_calls.append(fd)
        if fd not in self.fd_nodes: raise AssertionError('NO_CLOSE_RETRY')
        if self.fd_nodes[fd] is self.close_fail_node: raise self.close_error
        del self.fd_nodes[fd]
        return None
    def lseek(self, fd, position, whence):
        if position != 0 or whence != 0: raise AssertionError('FIXED_REWIND')
        self.read_number += 1
        if self.mutate_read_on == self.read_number:
            self.journal.data = b'X' + self.journal.data[1:]
        self.offsets[fd] = 0
        return 0
    def read(self, fd, count):
        node, offset = self.fd_nodes[fd], self.offsets[fd]
        value = node.data[offset:offset + count]
        self.offsets[fd] += len(value)
        return value
    def mkdir(self, name, mode, dir_fd=None):
        self.mkdir_calls.append(name)
        parent = self.fd_nodes[dir_fd]
        if name in parent.children: raise OSError(errno.EEXIST, 'MODEL_EXISTS')
        self.child(parent, name, stat.S_IFDIR | mode)
    def fsync(self, fd):
        self.fsync_calls.append(self.fd_nodes[fd])
        if self.fsync_fail_on == len(self.fsync_calls): raise OSError(errno.EIO, 'MODEL_FSYNC')
    def getpid(self): return 7701
    def geteuid(self): return 0
    def uname(self): return ('Linux', 'MODEL', '4.14.174', 'MODEL', 'armv7l')
    def listdir(self, *args, **kwargs): raise AssertionError('NO_HISTORY_ENUMERATION')
    def unlink(self, *args, **kwargs): raise AssertionError('NO_UNLINK')
    def chmod(self, *args, **kwargs): raise AssertionError('NO_PERMISSION_REPAIR')


class _Call(object):
    def __init__(self, function): self.function = function
    def __call__(self, *args): return self.function(*args)


class _ModelLibc(object):
    def __init__(self, fs, clock):
        self.fs, self.clock, self.number = fs, clock, 0
        self.locks, self.renames = [], []
        self.collide = self.expire_after_rename = self.lock_busy = False
        self.flock, self.syscall = _Call(self._flock), _Call(self._syscall)
    def _flock(self, fd, flags):
        if flags != 2 | 4: raise AssertionError('FLOCK_NOT_RECORD_LOCK')
        self.locks.append((fd, self.fs.fd_nodes[fd]))
        if self.lock_busy:
            self.number = errno.EAGAIN
            return -1
        return 0
    def _syscall(self, number, source_fd, name, dest_fd, destination_name, flags):
        if number != 382 or flags != 1 or name != destination_name: raise AssertionError('ARM_NOREPLACE_ONLY')
        source, destination = self.fs.fd_nodes[source_fd], self.fs.fd_nodes[dest_fd]
        key = name.decode('ascii')
        self.renames.append((source, key, destination))
        if self.collide:
            destination.children[key] = self.fs.node(stat.S_IFDIR | 0o700)
        if key in destination.children:
            self.number = errno.EEXIST
            return -1
        destination.children[key] = source.children.pop(key)
        if self.expire_after_rename: self.clock.value = 8.0
        return 0


class _Key(object):
    def __init__(self, value): self.value = value
    def key(self): return self.value


class _Journal(object):
    pass


class _Fixture(object):
    def __init__(self, raw):
        self.clock, self.module = _Clock(), types.ModuleType('completed_receive_archive_MODEL')
        self.fs = _ModelOS(self.clock)
        self.libc = _ModelLibc(self.fs, self.clock)
        self.module.__file__ = str(BASE / ARCHIVE_SOURCE)
        exec(compile(raw, self.module.__file__, 'exec'), self.module.__dict__)
        self.module.os = self.fs
        self.module.time = types.SimpleNamespace(monotonic=self.clock.monotonic)
        self.module.sys = types.SimpleNamespace(platform='linux', byteorder='little')
        self.module.ctypes = types.SimpleNamespace(CDLL=lambda *args, **kwargs: self.libc,
            set_errno=lambda value: setattr(self.libc, 'number', value), get_errno=lambda: self.libc.number,
            c_int=ctypes.c_int, c_long=ctypes.c_long, c_char_p=ctypes.c_char_p, c_uint=ctypes.c_uint)
        self.owner = types.SimpleNamespace(worker=threading.current_thread(), pid=self.fs.getpid(),
            archive_completed_receives=True, original_until=10.0, cleanup_until=60.0,
            terminal_owner_MODEL=True)
        self.capture_refused = False
        original = self.module.FixedCompletedReceiveArchive
        fixture = self
        class ExplicitOwnerModelArchive(original):
            # These TWO methods alone model the already-authenticated caller
            # boundary. All administrative production methods run unchanged.
            def _capture(self):
                if fixture.capture_refused: fixture.module._fail('parent_unknown')
                self.run_name = fixture.fs.run_name
                self.run_identity = fixture.module._directory(fixture.fs.run.metadata(), True)
                self.private_root_identity = fixture.module._directory(fixture.fs.client.metadata(), True)
                self.tmp_identity = fixture.module._directory(fixture.fs.tmp.metadata(), temporary=True)
                self.attempt = types.SimpleNamespace(token=fixture.fs.token, operation_id='op-model')
                identity, actor = _Key(('MODEL_IDENTITY_DATA',)), _Key(('MODEL_ACTOR_DATA',))
                self.deployment = types.SimpleNamespace(manifest=types.SimpleNamespace(identity=identity, candidate_sha='b' * 64))
                self.parent = types.SimpleNamespace(actor=actor)
                record = _Journal()
                record.stage, record.ready, record.identity = 'reconciled', False, identity
                record.association = types.SimpleNamespace(binding=(('run_token', fixture.fs.token),
                    ('candidate_sha', 'b' * 64), ('operation_id', 'op-model')), executor=actor)
                self.core = types.SimpleNamespace(Journal=_Journal)
                self.codec = types.SimpleNamespace(decode_journal=lambda data: record,
                    encode_journal=lambda current: fixture.fs.journal_raw)
            def _check_originals(self):
                if (self.owner is not fixture.owner or self.owner.terminal_owner_MODEL is not True or
                        self.owner.worker is not threading.current_thread() or self.pid != fixture.fs.getpid()):
                    fixture.module._fail('terminal_unknown')
        self.model_type = ExplicitOwnerModelArchive
        self.archive = self.model_type(self.owner, object())
        if self.model_type.archive is not original.archive or self.model_type._open is not original._open:
            raise AssertionError('ACTUAL_ADMIN_METHODS_REQUIRED')


class ReceiveCompletedArchiveContracts(unittest.TestCase):
    def test_administrative_io_only(self):
        for name, pin in PINS.items():
            source = (BASE / name).read_bytes()
            self.assertEqual((len(source), hashlib.sha256(source).hexdigest()), pin)
        raw = (BASE / ARCHIVE_SOURCE).read_bytes()
        contracts = []
        def fixture(): return _Fixture(raw)
        def run_error(value, reason=None):
            with self.assertRaises(BaseException) as caught: value.archive.archive()
            self.assertIs(value.archive.failure, caught.exception)
            if reason is not None: self.assertEqual(value.archive.reason, reason)
            self.assertTrue(value.archive.ended)
            self.assertTrue(value.archive.close_called)
            return caught.exception
        def finite_false(value):
            facts = value.archive.public_facts()
            self.assertIs(facts['native_restore_grant'], False)
            self.assertIs(facts['receive_admission'], False)
            self.assertEqual(facts['historical_entries_examined'], 0)
            self.assertTrue(all(name != 'old-history-model-do-not-read' for name in value.fs.stat_calls))
        def mark(name):
            contracts.append(name)
            print('HOST_RECEIVE_ARCHIVE_CASE=' + name)

        with self.subTest('same_inode_complete'):
            f = fixture(); original_run, original_journal = f.fs.run, f.fs.journal.data
            self.assertIs(f.archive.archive(), True)
            self.assertNotIn(f.fs.run_name, f.fs.client.children)
            self.assertIs(f.fs.tmp.children['p011-mta-client-completed'].children[f.fs.run_name], original_run)
            self.assertEqual(f.fs.journal.data, original_journal)
            self.assertEqual(f.fs.fsync_calls, [f.fs.tmp, f.fs.client, f.fs.tmp.children['p011-mta-client-completed']])
            self.assertEqual(len(f.libc.locks), 2)
            self.assertEqual(len(f.libc.renames), 1)
            self.assertTrue(f.archive.resources_closed()); self.assertFalse(f.fs.fd_nodes)
            self.assertEqual(len(f.fs.close_calls), len(set(f.fs.close_calls)))
            finite_false(f); mark('same_inode_complete')

        with self.subTest('existing_archive_parent'):
            f = fixture(); parent = f.fs.child(f.fs.tmp, 'p011-mta-client-completed', stat.S_IFDIR | 0o700)
            untouched = f.fs.child(parent, 'OTHER_MODEL_HISTORY', stat.S_IFDIR | 0o700)
            self.assertIs(f.archive.archive(), True)
            self.assertEqual(f.fs.mkdir_calls, [])
            self.assertEqual(f.fs.fsync_calls, [f.fs.client, parent])
            self.assertIs(parent.children['OTHER_MODEL_HISTORY'], untouched)
            finite_false(f); mark('existing_archive_parent')

        with self.subTest('preopen_zero_fd'):
            f = fixture(); f.fs.pre_stat_failure = True
            error = run_error(f, 'io_error'); row = f.archive.rows[-1]
            self.assertIs(row['preopen_error'], error)
            self.assertIs(row['open_called'], False); self.assertIsNone(row['fd'])
            self.assertIs(row['close_called'], False)
            self.assertTrue(f.archive.resources_closed()); self.assertFalse(f.fs.fd_nodes)
            finite_false(f); mark('preopen_zero_fd')

        with self.subTest('original_open_error_zero_fd'):
            f = fixture(); f.fs.open_failure = True
            error = run_error(f, 'io_error'); row = f.archive.rows[-1]
            self.assertIs(row['open_error'], error)
            self.assertIs(row['open_called'], True); self.assertIs(row['open_returned'], False)
            self.assertIsNone(row['fd']); self.assertTrue(f.archive.resources_closed())
            finite_false(f); mark('original_open_error_zero_fd')

        with self.subTest('returned_fd_unknown'):
            f = fixture(); f.fs.fail_first_fstat = True
            run_error(f, 'io_error'); row = f.archive.rows[0]
            self.assertIs(row['open_returned'], True); self.assertIs(row['unknown'], True)
            self.assertIs(row['closed'], True); self.assertIsNotNone(row['ebadf_error'])
            self.assertFalse(f.archive.resources_closed()); self.assertFalse(f.fs.fd_nodes)
            finite_false(f); mark('returned_fd_unknown')

        with self.subTest('journal_cas_changed'):
            f = fixture(); f.fs.mutate_read_on = 2
            run_error(f, 'journal_unknown')
            self.assertFalse(f.libc.renames); self.assertIs(f.fs.client.children[f.fs.run_name], f.fs.run)
            self.assertTrue(f.archive.resources_closed()); self.assertFalse(f.fs.fd_nodes)
            finite_false(f); mark('journal_cas_changed')

        with self.subTest('marker_present'):
            f = fixture(); f.fs.child(f.fs.tmp, 'p011-mta-p2p-device.pending', stat.S_IFREG | 0o600, b'MODEL_PENDING')
            run_error(f, 'marker_present')
            self.assertFalse(f.libc.renames); self.assertFalse(f.fs.mkdir_calls)
            self.assertEqual(f.fs.tmp.children['p011-mta-p2p-device.pending'].data, b'MODEL_PENDING')
            self.assertTrue(f.archive.resources_closed()); finite_false(f); mark('marker_present')

        with self.subTest('destination_no_overwrite'):
            f = fixture(); parent = f.fs.child(f.fs.tmp, 'p011-mta-client-completed', stat.S_IFDIR | 0o700)
            destination = f.fs.child(parent, f.fs.run_name, stat.S_IFDIR | 0o700)
            run_error(f, 'destination_exists')
            self.assertFalse(f.libc.renames); self.assertIs(parent.children[f.fs.run_name], destination)
            self.assertIs(f.fs.client.children[f.fs.run_name], f.fs.run)
            self.assertTrue(f.archive.resources_closed()); finite_false(f); mark('destination_no_overwrite')

        with self.subTest('rename_noreplace_race'):
            f = fixture(); f.libc.collide = True
            run_error(f, 'rename_failed')
            self.assertEqual(f.archive.rename_errno, errno.EEXIST)
            self.assertIs(f.fs.client.children[f.fs.run_name], f.fs.run)
            self.assertTrue(f.archive.public_facts()['archive_outcome_unknown'])
            self.assertEqual(len(f.libc.renames), 1); self.assertTrue(f.archive.resources_closed())
            finite_false(f); mark('rename_noreplace_race')

        with self.subTest('postrename_journal_changed'):
            f = fixture(); f.fs.mutate_read_on = 3
            run_error(f, 'journal_unknown')
            self.assertTrue(f.archive.same_inode_archived); self.assertTrue(f.archive.source_absent)
            self.assertFalse(f.archive.rename_outcome_known)
            self.assertTrue(f.archive.public_facts()['archive_outcome_unknown'])
            self.assertTrue(f.archive.resources_closed()); finite_false(f); mark('postrename_journal_changed')

        with self.subTest('destination_fsync_error'):
            f = fixture(); f.fs.fsync_fail_on = 3
            run_error(f, 'io_error')
            self.assertTrue(f.archive.fsync_source); self.assertFalse(f.archive.fsync_destination)
            self.assertFalse(f.archive.rename_outcome_known); self.assertTrue(f.archive.resources_closed())
            finite_false(f); mark('destination_fsync_error')

        with self.subTest('expiry_closes_known_fds'):
            f = fixture(); f.fs.expire_after_open = 3
            run_error(f, 'deadline')
            self.assertEqual(len(f.fs.opened), 3); self.assertFalse(f.fs.fd_nodes)
            self.assertFalse(f.libc.renames); self.assertTrue(f.archive.resources_closed())
            finite_false(f); mark('expiry_closes_known_fds')

        with self.subTest('postrename_expiry_unknown'):
            f = fixture(); f.libc.expire_after_rename = True
            run_error(f, 'deadline')
            self.assertTrue(f.archive.rename_called); self.assertFalse(f.archive.rename_outcome_known)
            self.assertTrue(f.archive.resources_closed()); self.assertFalse(f.fs.fd_nodes)
            finite_false(f); mark('postrename_expiry_unknown')

        with self.subTest('close_failure_no_retry'):
            f = fixture(); f.fs.close_fail_node = f.fs.run
            run_error(f, 'close_unknown')
            self.assertIs(f.archive.close_errors[0], f.fs.close_error)
            self.assertEqual(len(f.fs.fd_nodes), 1)
            self.assertFalse(f.archive.resources_closed()); self.assertFalse(f.archive.public_facts()['archived'])
            before = tuple(f.fs.close_calls)
            self.assertIs(f.archive.close(), False); self.assertEqual(tuple(f.fs.close_calls), before)
            self.assertEqual(len(before), len(set(before)))
            finite_false(f); mark('close_failure_no_retry')

        with self.subTest('unsafe_archive_parent_preserved'):
            f = fixture(); parent = f.fs.child(f.fs.tmp, 'p011-mta-client-completed', stat.S_IFDIR | 0o755)
            run_error(f, 'unsafe_path')
            self.assertIs(f.fs.tmp.children['p011-mta-client-completed'], parent)
            self.assertFalse(f.libc.renames); self.assertTrue(f.archive.resources_closed())
            finite_false(f); mark('unsafe_archive_parent_preserved')

        with self.subTest('lock_refusal_preserved'):
            f = fixture(); f.libc.lock_busy = True
            run_error(f, 'lock_busy')
            self.assertFalse(f.libc.renames); self.assertFalse(f.fs.mkdir_calls)
            self.assertTrue(f.archive.resources_closed()); finite_false(f); mark('lock_refusal_preserved')

        self.assertEqual(len(contracts), 16)
        self.assertEqual(len(set(contracts)), 16)
        print('RECEIVE_COMPLETED_ARCHIVE_CONTRACTS=16')


if __name__ == '__main__':
    unittest.main(verbosity=2)
