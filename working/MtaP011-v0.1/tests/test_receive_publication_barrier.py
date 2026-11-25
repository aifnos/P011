"""One focused HOST model method for the actual publication Barrier SOURCE.

All IO/stat/FD/syscall receipts and the Owner are explicit models. This test
never constructs a real FixedStateServiceOwner, opens a real directory, reads
pending contents, disposes CLIENT history, grants a gate or accesses a device.
The actual complete Barrier module is loaded privately. Only its module-local
os flags are projected to a labeled Linux model; global os is not modified.
Real HOST Thread identity is used solely for the wrong-worker negative case.
These observations are not production publication/admission/restore evidence.
"""
import errno
import hashlib
import importlib.util
from pathlib import Path
import stat
import threading
import time
import types
import unittest


BASE = Path(__file__).resolve().parents[1]
SOURCE = BASE / 'candidate/receive-publication-barrier-v1/runtime/receive_barrier.py'
SOURCE_PIN = (24113, 'd2721874aa6971b0742c4ae4b1dea9ba9bee277046ddb7253c3975b3dd6bf397')
LINUX_FLAGS_MODEL = types.SimpleNamespace(O_RDONLY=0, O_DIRECTORY=0x10000,
                                        O_NOFOLLOW=0x8000, O_CLOEXEC=0x80000)


def fixed_module():
    raw = SOURCE.read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != SOURCE_PIN:
        raise AssertionError('Fixed barrier SOURCE differs')
    spec = importlib.util.spec_from_file_location('_host_actual_publication_barrier', str(SOURCE))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.os = LINUX_FLAGS_MODEL  # Private module only; production platform is not certified.
    return module


def owner_model():
    namespace = {'__name__': 'startup_readonly_private_owner'}
    exec('class FixedStateServiceOwner(object):\n'
         '    def _now(self):\n'
         '        self.now_calls += 1\n'
         '        return self.now_value\n', namespace)
    cls = namespace['FixedStateServiceOwner']
    owner = cls()
    owner.worker = threading.current_thread()
    owner.pid = 123
    owner.original_until = owner.until = 100.0
    owner.clock = time.monotonic  # Original callable identity; _now value remains explicitly modeled.
    owner.now_value, owner.now_calls = 10.0, 0
    owner.started, owner.server_called, owner.server, owner.close_called = True, False, None, False
    owner._startup_namespace_original = namespace
    owner._startup_owner_type_original = cls
    return owner


def raw_metadata(inode, mode, nlink=2, size=4096):
    return types.SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode,
        st_uid=0, st_gid=0, st_nlink=nlink, st_size=size, st_mtime_ns=10, st_ctime_ns=10)


class ModelIo(object):
    """Private virtual path tree/FD table: no underlying OS IO is performed."""
    def __init__(self, module, owner, **options):
        self.module, self.owner, self.options = module, owner, options
        self.directories = {
            '/': raw_metadata(1, stat.S_IFDIR | 0o755),
            '/var': raw_metadata(2, stat.S_IFDIR | 0o755),
            '/var/volatile': raw_metadata(3, stat.S_IFDIR | 0o1777),
            module.PHYSICAL_TMP: raw_metadata(4, stat.S_IFDIR | 0o1777),
            module.CLIENT_ROOT: raw_metadata(5, stat.S_IFDIR | 0o700)}
        self.alias_targets = {'/tmp': '/var/tmp', '/var/tmp': module.PHYSICAL_TMP}
        self.aliases = dict((path, raw_metadata(10 + index, stat.S_IFLNK | 0o777, 1, len(target)))
                            for index, (path, target) in enumerate(self.alias_targets.items()))
        self.fd_entries, self.next_fd = {}, 41
        self.opened, self.closed, self.close_attempts, self.receipts = [], [], {}, []
        self.close_clock_counts, self.listdir_count, self.pending_stat_count = [], 0, 0
        self.content_reads = 0
        self.barrier = None

    def validate(self):
        self.receipts.append(('platform-model',))
        return None

    def pid(self):
        return self.owner.pid

    def _path(self, fd, name):
        if fd not in self.fd_entries:
            raise OSError(errno.EBADF, 'HOST model descriptor absent')
        parent = self.fd_entries[fd][0]
        return ('/' if parent == '/' else parent + '/') + name

    def stat_root(self):
        self.receipts.append(('stat', '/'))
        if self.options.get('unknown_stat'):
            row = raw_metadata(1, stat.S_IFDIR | 0o755)
            row.st_ino = None
            return row
        return self.directories['/']

    def stat_at(self, fd, name):
        path = self._path(fd, name)
        self.receipts.append(('stat', path))
        if path == self.module.PENDING_PATH:
            self.pending_stat_count += 1
            if self.options.get('pending_permission'):
                raise OSError(errno.EACCES, 'HOST model metadata denied')
            pending = self.options.get('pending')
            if pending == 'regular': return raw_metadata(20, stat.S_IFREG | 0o600, 1, 340)
            if pending == 'symlink': return raw_metadata(21, stat.S_IFLNK | 0o777, 1, 20)
            raise OSError(errno.ENOENT, 'HOST model pending absent')
        if path in self.aliases:
            return self.aliases[path]
        if path == self.module.CLIENT_ROOT and self.options.get('client_missing'):
            raise OSError(errno.ENOENT, 'HOST model CLIENT absent')
        if path == self.module.CLIENT_ROOT and self.options.get('client_symlink'):
            return raw_metadata(23, stat.S_IFLNK | 0o777, 1, 12)
        if path not in self.directories:
            raise AssertionError('Barrier attempted to inspect historical entry')
        return self.directories[path]

    def readlink_at(self, fd, name):
        path = self._path(fd, name)
        self.receipts.append(('readlink', path))
        if self.options.get('alias_replacement') and path == '/tmp':
            return '/untrusted'
        return self.alias_targets[path]

    def open_dir(self, fd, name, flags):
        path = '/' if fd is None and name == '/' else self._path(fd, name)
        if path not in self.directories:
            raise AssertionError('Barrier attempted to open pending/history/symlink content')
        expected = (LINUX_FLAGS_MODEL.O_RDONLY | LINUX_FLAGS_MODEL.O_DIRECTORY |
                    LINUX_FLAGS_MODEL.O_NOFOLLOW | LINUX_FLAGS_MODEL.O_CLOEXEC)
        if flags != expected:
            raise AssertionError('Directory flags lost NOFOLLOW/CLOEXEC')
        number, self.next_fd = self.next_fd, self.next_fd + 1
        self.fd_entries[number] = (path, self.directories[path])
        self.opened.append(number)
        self.receipts.append(('open', path, number, flags))
        if self.options.get('replace_after_open') == path:
            old = self.directories[path]
            self.directories[path] = raw_metadata(old.st_ino + 100, old.st_mode)
        if self.options.get('late_open') == path:
            self.owner.now_value = self.owner.until
        return number

    def fstat(self, fd):
        self.receipts.append(('fstat', fd))
        if fd not in self.fd_entries:
            raise OSError(errno.EBADF, 'HOST model descriptor closed')
        return self.fd_entries[fd][1]

    def rewind(self, fd):
        if fd not in self.fd_entries:
            raise OSError(errno.EBADF, 'HOST model descriptor closed')
        self.receipts.append(('rewind', fd))
        return 1 if self.options.get('bad_rewind') else 0

    def listdir(self, fd):
        if fd not in self.fd_entries or self.fd_entries[fd][0] != self.module.CLIENT_ROOT:
            raise AssertionError('Barrier listed a non-CLIENT directory')
        self.listdir_count += 1
        self.receipts.append(('listdir', fd))
        if self.options.get('replace_owner'):
            self.barrier.owner = object()
        if self.options.get('replace_worker'):
            self.owner.worker = object()
        if self.options.get('bad_listing'):
            return None
        if self.options.get('listing_over_limit'):
            return [str(index) for index in range(self.module.MAX_DIRECTORY_ENTRIES + 1)]
        if self.options.get('duplicate_listing'):
            return ['same', 'same']
        if self.options.get('new_entry_race') and self.listdir_count == 2:
            return ['new-entry']
        return list(self.options.get('history', ()))

    def close(self, fd):
        self.close_attempts[fd] = self.close_attempts.get(fd, 0) + 1
        self.close_clock_counts.append(self.owner.now_calls)
        self.receipts.append(('close', fd))
        if fd not in self.fd_entries:
            raise OSError(errno.EBADF, 'HOST model descriptor absent')
        path = self.fd_entries[fd][0]
        if self.options.get('close_failure') == path:
            raise OSError(errno.EIO, 'HOST model close failed')
        del self.fd_entries[fd]
        self.closed.append(fd)
        return False if self.options.get('bad_close_return') == path else None


class PublicationBarrierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = fixed_module()

    def fixture(self, **options):
        owner = owner_model()
        io = ModelIo(self.module, owner, **options)
        barrier = self.module._host_model(owner, io)
        io.barrier = barrier
        return owner, io, barrier

    def assert_once_closed(self, io, barrier, expected=True):
        self.assertTrue(all(count == 1 for count in io.close_attempts.values()))
        if expected:
            self.assertEqual(set(io.opened), set(io.closed))
            self.assertEqual(io.fd_entries, {})
            self.assertIs(barrier.resources_closed, True)
        before = dict(io.close_attempts)
        barrier._close_all()
        self.assertEqual(io.close_attempts, before)
        if io.close_clock_counts:
            self.assertEqual(len(set(io.close_clock_counts)), 1, 'Close must not call/renew Owner._now')
        self.assertEqual(io.content_reads, 0)
        self.assertFalse(any(row[0] == 'read' for row in io.receipts))

    def test_publication_barrier_models(self):
        cases = []
        def expect(name, barrier, reason, closed=True):
            facts = barrier.public_facts()
            self.assertEqual(facts['reason'], reason, name)
            self.assertIs(facts['resources_closed'], closed, name)
            self.assertIs(barrier.ended, True)
            self.assertEqual(set(facts), {'reason', 'opened_count', 'closed_count',
                                         'observation_count', 'resources_closed'})
            cases.append(name)

        owner, io, barrier = self.fixture()
        self.assertIs(barrier.run(), barrier)
        expect('clear-two-rounds-data-only', barrier, 'clear')
        self.assertEqual(len(barrier.rounds), 2)
        self.assertEqual(len(io.opened), 5)
        self.assert_once_closed(io, barrier)
        with self.assertRaises(self.module.BarrierError) as refused:
            barrier.run()
        self.assertEqual(refused.exception.code, 'already_attempted')
        cases.append('one-shot-no-new-IO')
        self.assert_once_closed(io, barrier)

        for pending, reason in (('regular', 'pending_exists'), ('symlink', 'pending_symlink')):
            owner, io, barrier = self.fixture(pending=pending)
            barrier.run(); expect('metadata-only-' + pending, barrier, reason)
            self.assertFalse(any(row[0] == 'open' and row[1] == self.module.PENDING_PATH for row in io.receipts))
            self.assert_once_closed(io, barrier)

        for names in (['runtime'], ['old-run.json', 'logs']):
            owner, io, barrier = self.fixture(history=names)
            barrier.run(); expect('CLIENT-history-' + names[0], barrier, 'client_history')
            self.assertEqual(barrier.rounds[0]['names'], names)
            self.assertFalse(any(row[0] == 'stat' and row[1].startswith(self.module.CLIENT_ROOT + '/')
                                 for row in io.receipts))
            self.assert_once_closed(io, barrier)

        negative = (
            ('unknown-stat', {'unknown_stat': True}, 'unsafe_anchor'),
            ('pending-stat-permission', {'pending_permission': True}, 'io_error'),
            ('CLIENT-missing', {'client_missing': True}, 'client_root_missing'),
            ('CLIENT-symlink-no-follow', {'client_symlink': True}, 'unsafe_anchor'),
            ('unknown-listing', {'bad_listing': True}, 'inventory_unknown'),
            ('too-many-entries', {'listing_over_limit': True}, 'inventory_unknown'),
            ('duplicate-entry', {'duplicate_listing': True}, 'inventory_unknown'),
            ('rewind-unknown', {'bad_rewind': True}, 'inventory_unknown'),
            ('new-entry-between-rounds', {'new_entry_race': True}, 'client_history'),
            ('physical-root-replaced', {'replace_after_open': '/'}, 'anchor_changed'),
            ('CLIENT-root-replaced', {'replace_after_open': self.module.CLIENT_ROOT}, 'anchor_changed'),
            ('fixed-alias-replaced', {'alias_replacement': True}, 'alias_changed'),
            ('original-Owner-replaced', {'replace_owner': True}, 'owner_context'),
            ('original-worker-replaced', {'replace_worker': True}, 'owner_context'),
        )
        for name, options, reason in negative:
            with self.subTest(name=name):
                owner, io, barrier = self.fixture(**options)
                barrier.run(); expect(name, barrier, reason)
                self.assert_once_closed(io, barrier)

        owner, io, barrier = self.fixture(close_failure=self.module.CLIENT_ROOT)
        barrier.run(); expect('close-failure-independent-originals', barrier, 'close_unknown', False)
        self.assertEqual(len(io.closed), 4)
        self.assertEqual(len(io.fd_entries), 1)
        self.assertEqual(len(barrier.close_failures), 1)
        self.assert_once_closed(io, barrier, False)

        owner, io, barrier = self.fixture(bad_close_return=self.module.CLIENT_ROOT)
        barrier.run(); expect('physical-close-unknown-return-not-success', barrier, 'close_unknown', False)
        self.assertEqual(len(io.closed), 5)
        self.assert_once_closed(io, barrier, False)

        owner, io, barrier = self.fixture()
        owner.now_value = owner.until
        barrier.run(); expect('pre-open-original-deadline', barrier, 'deadline')
        self.assertEqual(io.opened, [])
        self.assert_once_closed(io, barrier)

        for path, expected in (('/', 1), (self.module.CLIENT_ROOT, 5)):
            owner, io, barrier = self.fixture(late_open=path)
            barrier.run(); expect('post-open-deadline-' + path, barrier, 'deadline')
            self.assertEqual(len(io.opened), expected)
            self.assertTrue(all(type(row['metadata_original']) is tuple for row in barrier.rows
                                if row['open_returned']))
            self.assert_once_closed(io, barrier)

        owner, io, barrier = self.fixture()
        failures = []
        def other_worker():
            try: barrier.run()
            except BaseException as error: failures.append(error)
        thread = threading.Thread(target=other_worker, name='HOST-barrier-wrong-worker')
        thread.start(); thread.join(2.0)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        expect('original-worker-other-thread', barrier, 'wrong_worker')
        self.assertEqual(io.opened, [])
        self.assert_once_closed(io, barrier)

        self.assertEqual(len(cases), 26)
        print('RECEIVE_PUBLICATION_BARRIER_MODELS=' + repr({'cases': len(cases),
            'actual_complete_barrier': True, 'owner_io_model': True, 'module_flags_model': True,
            'global_os_changed': False, 'real_owner': False, 'gate': False,
            'device': False, 'rf': False, 'pending_disposition': False}), flush=True)


if __name__ == '__main__':
    unittest.main()
