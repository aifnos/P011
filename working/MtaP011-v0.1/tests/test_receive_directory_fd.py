# -*- coding: utf-8 -*-
"""New held-directory receive mechanics, for ROOT's single Linux HOST run.

The isolated complete storage/protocol definitions are actual source. Temporary
directories, openat/no-follow, hard-link no-clobber publication, fsync and close
are real Linux operations; no OS/UID/FD metadata is synthesized. There is no
State, Factory, F subprocess, network, RF, phone or target admission here.
Only this new method runs; no earlier TestCase/helper or passed method imports.
Callbacks make actual substitutions/cancellation in this fixture-owned tree.
All temporary paths are newly created by this test, never user directories.
"""
import builtins
import errno
import hashlib
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import types
import unittest
import zipfile

BASE = Path(__file__).resolve().parents[1]
STORAGE_SOURCE = (
    'candidate/receive-directory-fd-v1/runtime/mta_storage.py',
    'ea3d3df1177019125c9b3124b8ebaf33196dd1013db95ac24580e1fe1a96c8d1', 55562)
SOURCES = (
    ('p011_json', 'runtime/p011_json.py',
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88', 8061),
    ('mta_protocol', 'runtime/mta_protocol.py',
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57', 17958),
)
MARKER = ('HOST_RECEIVE_DIRECTORY_FD new_methods=1 old_methods=0 cases=7 '
          'linux_kernel=true device=false phone=false\n')


def _definitions():
    modules = {}
    original_import = builtins.__import__

    def fixed_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level:
            raise ImportError('relative model imports refused')
        if name in modules:
            return modules[name]
        if name.startswith(('mta_', 'p011_')):
            raise ImportError('unlisted project definition')
        return original_import(name, globals, locals, fromlist, level)

    sources = list(SOURCES) + [('mta_storage',) + STORAGE_SOURCE]
    for name, relative, digest, count in sources:
        raw = (BASE / relative).read_bytes()
        if digest is None or len(raw) != count or hashlib.sha256(raw).hexdigest() != digest:
            raise AssertionError('fixed input SOURCE pin differs')
        module = types.ModuleType(name)
        module.__file__ = str(BASE / relative)
        namespace_builtins = dict(vars(builtins))
        namespace_builtins['__import__'] = fixed_import
        module.__dict__['__builtins__'] = namespace_builtins
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
        modules[name] = module
    return modules['mta_storage']


def _fd_set():
    # listdir's own transient enumeration FD is excluded by actual fstat.
    result = set()
    for name in os.listdir('/proc/self/fd'):
        try:
            value = int(name)
            os.fstat(value)
        except (OSError, ValueError):
            continue
        result.add(value)
    return result


def _directory_identity(path):
    observed = os.lstat(path)
    # Child creation legitimately changes directory size/nlink/mtime; not identity.
    return (observed.st_dev, observed.st_ino, observed.st_mode,
            observed.st_uid, observed.st_gid)


def _archive_bytes():
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        archive.writestr('资料/中文.txt', ('真实目录绑定\n' * 100).encode('utf-8'))
        archive.writestr('第二.bin', b'\x00\x01\x02' * 100)
    return output.getvalue()


class _Fixture(object):
    def __init__(self, case, storage):
        self.case, self.storage = case, storage
        self.base = None
        self.root = None
        self.bindings, self.receivers = [], []
        self.allow_pending = False
        self.before_fds = _fd_set()
        self.cleanup_failures = []
        self.temp = tempfile.TemporaryDirectory(prefix='host-receive-directory-fd-')
        self.base = Path(self.temp.name)
        self.base_identity = _directory_identity(self.base)
        self.ancestor = self.base / '原祖先'
        self.ancestor.mkdir(mode=0o700)
        self.root = self.ancestor / '收件目录'
        self.root.mkdir(mode=0o700)
        self.sentinel = self.root / '原用户文件.txt'
        self.sentinel.write_bytes(b'unchanged-user-sentinel')
        self.root_identity = _directory_identity(self.root)
        self.until = time.monotonic() + 30.0

    def binding(self, root=None):
        value = self.storage.DirectoryBinding(str(root or self.root), self.until)
        self.bindings.append(value)
        return value

    def receiver(self, binding):
        value = self.storage.SafeZipReceiver(binding.root, reserve_bytes=0,
                                            directory_binding=binding)
        self.receivers.append(value)
        return value

    def plain_archive(self):
        value = self.root / '输入中文.zip'
        value.write_bytes(_archive_bytes())
        return value

    def assert_rows(self, rows):
        for row in rows:
            self.case.assertTrue(row['closed'])
            self.case.assertFalse(row['unknown'])
            if row['returned']:
                self.case.assertTrue(row['close_called'])
                self.case.assertIsNone(row['close_return'])
                self.case.assertIsInstance(row['ebadf'], OSError)
                self.case.assertEqual(errno.EBADF, row['ebadf'].errno)
            # These retained immediate close facts are checked; historical FD
            # integers are not re-fstat'ed after subsequent opens may reuse them.

    def __enter__(self):
        return self

    def __exit__(self, kind, primary, traceback):
        for receiver in reversed(self.receivers):
            try:
                returned = receiver.close()
                if not self.allow_pending:
                    self.case.assertIs(returned, True)
                    self.case.assertFalse(receiver.lifecycle_status()['resource_pending'])
                self.assert_rows(receiver._bound_rows)
            except BaseException as error:
                self.cleanup_failures.append(error)
        for binding in reversed(self.bindings):
            try:
                self.case.assertIs(binding.close(), True)
                self.case.assertTrue(binding.closed())
                self.assert_rows(binding.rows)
                for resource in binding.archives + binding.downloads:
                    self.assert_rows([resource.row])
            except BaseException as error:
                self.cleanup_failures.append(error)
        # Only this fresh exact test tree may be removed. The identity check
        # prevents an accidental broad/unrelated cleanup target.
        try:
            self.case.assertEqual(self.base_identity, _directory_identity(self.base))
            self.temp.cleanup()
            self.case.assertEqual(self.before_fds, _fd_set())
        except BaseException as error:
            self.cleanup_failures.append(error)
        if self.cleanup_failures:
            if primary is not None:
                primary.host_cleanup_failures = tuple(self.cleanup_failures)
                return False  # Preserve the first business/assertion exception.
            raise self.cleanup_failures[0]
        return False


class ReceiveDirectoryFdTests(unittest.TestCase):
    def test_bound_commit_and_replacement_refusal(self):
        self.assertEqual('posix', os.name)
        self.assertTrue(sys.platform.startswith('linux'))
        storage = _definitions()
        completed = 0

        # 1. Same w+b download object is borrowed by EOCD and ZipFile. It remains
        # open after actual commit; transport/caller performs its original close.
        with self.subTest(domain='normal_borrowed_download'):
            with _Fixture(self, storage) as f:
                binding = f.binding()
                receiver = f.receiver(binding)
                original_root = binding.identity_rows()
                download = binding.create_download()
                original_handle = download.handle
                original_fd = download.row['fd_original']
                raw = _archive_bytes()
                self.assertEqual(len(raw), original_handle.write(raw))
                original_handle.flush()
                os.fsync(original_fd)
                self.assertIs(binding.download_current(download), download)
                self.assertIs(receiver.directory_binding, binding)
                expected = [('真实目录绑定\n' * 100).encode('utf-8'), b'\x00\x01\x02' * 100]
                result = receiver.receive(download.path, 'bound-normal',
                                          expected_files=2, expected_bytes=sum(map(len, expected)),
                                          archive_resource=download)
                # Derive exact actual request byte count independently, not a
                # success flag or fixture-generated permission.
                self.assertEqual(sum(map(len, expected)), result['totalSize'])
                self.assertEqual(2, result['fileCount'])
                self.assertEqual(expected, [Path(path).read_bytes() for path in result['files']])
                self.assertEqual(original_root, binding.identity_rows())
                self.assertEqual(f.root_identity, _directory_identity(f.root))
                self.assertEqual(b'unchanged-user-sentinel', f.sentinel.read_bytes())
                self.assertIs(download.handle, original_handle)
                self.assertFalse(original_handle.closed)
                self.assertEqual(original_fd, original_handle.fileno())
                self.assertTrue(all(stat.S_IMODE(os.lstat(path).st_mode) == 0o600
                                    for path in result['files']))
                self.assertEqual(0o700, stat.S_IMODE(os.lstat(result['directory']).st_mode))
                self.assertFalse(any(value.name.startswith('.mta-stage-') for value in f.root.iterdir()))
                self.assertIs(receiver.close(), True)
                self.assertIs(binding.check(), binding)  # Borrower did not close chain.
                self.assertIs(binding.close_download(download), True)
                with self.assertRaises(OSError) as badfd:
                    os.fstat(original_fd)  # Immediately, before any allocating call.
                self.assertEqual(errno.EBADF, badfd.exception.errno)
                self.assertIs(binding.remove_download(download), True)
                self.assertFalse(Path(download.path).exists())
                closed_fact = download.row['ebadf']
                self.assertIs(binding.close_download(download), True)
                self.assertIs(download.row['ebadf'], closed_fact)
            completed += 1

        # 2. Replacing the bound root never directs writes into the replacement.
        with self.subTest(domain='root_replacement'):
            with _Fixture(self, storage) as f:
                binding = f.binding()
                receiver = f.receiver(binding)
                path = f.plain_archive()
                saved = f.ancestor / '旧收件目录'
                f.root.rename(saved)
                f.root.mkdir(mode=0o700)
                foreign = f.root / 'foreign.txt'
                foreign.write_bytes(b'foreign-root-content')
                before = (_directory_identity(f.root), foreign.read_bytes(), sorted(os.listdir(f.root)))
                with self.assertRaises(storage.StorageError) as caught:
                    receiver.receive(str(path), 'root-replaced')
                self.assertIs(receiver._bound_failure, caught.exception)
                self.assertEqual(before, (_directory_identity(f.root), foreign.read_bytes(),
                                          sorted(os.listdir(f.root))))
                self.assertEqual(b'unchanged-user-sentinel', (saved / f.sentinel.name).read_bytes())
                self.assertFalse(receiver._bound_rows)
            completed += 1

        # 3. The original full chain, not merely the last directory, is checked.
        with self.subTest(domain='ancestor_replacement'):
            with _Fixture(self, storage) as f:
                binding = f.binding()
                receiver = f.receiver(binding)
                path = f.plain_archive()
                saved = f.base / '旧祖先'
                f.ancestor.rename(saved)
                f.ancestor.mkdir(mode=0o700)
                f.root.mkdir(mode=0o700)
                foreign = f.root / 'foreign.txt'
                foreign.write_bytes(b'foreign-ancestor-content')
                before = (_directory_identity(f.root), foreign.read_bytes(), sorted(os.listdir(f.root)))
                with self.assertRaises(storage.StorageError) as caught:
                    receiver.receive(str(path), 'ancestor-replaced')
                self.assertIs(receiver._bound_failure, caught.exception)
                self.assertEqual(before, (_directory_identity(f.root), foreign.read_bytes(),
                                          sorted(os.listdir(f.root))))
                self.assertEqual(b'unchanged-user-sentinel',
                                 (saved / f.root.name / f.sentinel.name).read_bytes())
                self.assertFalse(receiver._bound_rows)
            completed += 1

        # 4. Existing root and ancestor symlinks are never traversed. Known open
        # errors retain partially constructed owners and immediate close facts.
        with self.subTest(domain='initial_symlink'):
            with _Fixture(self, storage) as f:
                link = f.base / 'link'
                link.symlink_to(f.ancestor, target_is_directory=True)
                before = (f.sentinel.read_bytes(), sorted(os.listdir(f.root)))
                for requested in (f.base / 'root-link', link / f.root.name):
                    if requested.name == 'root-link':
                        requested.symlink_to(f.root, target_is_directory=True)
                    with self.assertRaises(OSError) as caught:
                        storage.DirectoryBinding(str(requested), f.until)
                    owner = caught.exception.directory_binding
                    self.assertTrue(owner.closed())
                    f.assert_rows(owner.rows)
                    self.assertEqual(before, (f.sentinel.read_bytes(), sorted(os.listdir(f.root))))
            completed += 1

        # 5. A real callback substitutes a result directory with a symlink
        # before commit. No write/delete follows it; cleanup remains pending.
        with self.subTest(domain='owned_result_symlink'):
            with _Fixture(self, storage) as f:
                binding = f.binding()
                receiver = f.receiver(binding)
                path = f.plain_archive()
                outside = f.base / 'outside'
                outside.mkdir(mode=0o700)
                sentinel = outside / 'never-touch.txt'
                sentinel.write_bytes(b'outside-sentinel')
                foreign_before = (_directory_identity(outside), sentinel.read_bytes(),
                                  sorted(os.listdir(outside)))
                changed = []

                def substitute_result():
                    if not changed:
                        roots = [entry for entry in receiver._bound_entries
                                 if entry['kind'] == 'directory' and entry['created'] and
                                 entry['name'].startswith(b'received-') and
                                 entry['row'] is not None and not entry['row']['unknown']]
                        if roots:
                            entry = roots[0]
                            name = entry['name'].decode('utf-8')
                            original = f.root / name
                            displaced = f.root / (name + '-original')
                            original.rename(displaced)
                            original.symlink_to(outside, target_is_directory=True)
                            changed.append((original, displaced))
                    return False

                with self.assertRaises(storage.StorageError) as caught:
                    receiver.receive(str(path), 'result-substituted',
                                     cancelled=substitute_result)
                self.assertTrue(changed)
                self.assertIs(receiver._bound_failure, caught.exception)
                self.assertTrue(receiver.lifecycle_status()['resource_pending'])
                self.assertIs(receiver.close(), False)
                self.assertEqual(foreign_before, (_directory_identity(outside), sentinel.read_bytes(),
                                                 sorted(os.listdir(outside))))
                self.assertTrue(changed[0][0].is_symlink())
                self.assertTrue(changed[0][1].is_dir())  # Not recursively swept.
                self.assertEqual(b'unchanged-user-sentinel', f.sentinel.read_bytes())
                f.allow_pending = True
            completed += 1

        # 6. Cancellation after an actual written chunk removes only original
        # staging entries and closes them; original business exception survives.
        with self.subTest(domain='cancelled_cleanup'):
            with _Fixture(self, storage) as f:
                binding = f.binding()
                receiver = f.receiver(binding)
                path = f.plain_archive()
                before = (f.root_identity, f.sentinel.read_bytes(),
                          sorted(os.listdir(f.root)))
                cancel = [False]

                def progress(done, total):
                    self.assertGreater(done, 0)
                    self.assertLessEqual(done, total)
                    cancel[0] = True

                with self.assertRaises(storage.TransferCancelled) as caught:
                    receiver.receive(str(path), 'cancelled', cancelled=lambda: cancel[0],
                                     progress=progress)
                self.assertIs(receiver._bound_failure, caught.exception)
                self.assertFalse(receiver.lifecycle_status()['resource_pending'])
                self.assertEqual(before, (_directory_identity(f.root), f.sentinel.read_bytes(),
                                          sorted(os.listdir(f.root))))
                self.assertTrue(receiver._bound_rows)
                f.assert_rows(receiver._bound_rows)
            completed += 1

        # 7. Fixed Received initialization only: mkdirat0700 under existing held
        # user, valid existing readonly validation, wrong type/no arbitrarychild.
        with self.subTest(domain='fixed_received_initializer'):
            with _Fixture(self, storage) as f:
                parent = f.binding()
                before = parent.identity_rows()
                child = parent.ensure_private_child('Received')
                f.bindings.append(child)
                self.assertEqual(before, parent.identity_rows())
                self.assertEqual(before, child.identity_rows()[:-1])
                self.assertEqual(0o700, stat.S_IMODE(os.lstat(child.root).st_mode))
                ticket = parent.initializations[-1]
                self.assertTrue(ticket['called'])
                self.assertTrue(ticket['returned'])
                self.assertTrue(ticket['created'])
                self.assertIs(ticket['child'], child)
                self.assertEqual(ticket['identity'], child.rows[-1]['identity'])
                again = parent.ensure_private_child('Received')
                f.bindings.append(again)
                self.assertFalse(parent.initializations[-1]['called'])
                self.assertFalse(parent.initializations[-1]['created'])
                self.assertEqual(child.identity_rows(), again.identity_rows())
                with self.assertRaises(storage.StorageError):
                    parent.ensure_private_child('different')
                self.assertFalse((f.root / 'different').exists())
                self.assertEqual(b'unchanged-user-sentinel', f.sentinel.read_bytes())
            with _Fixture(self, storage) as f:
                parent = f.binding()
                received = f.root / 'Received'
                received.write_bytes(b'foreign-existing-file')
                before = (_directory_identity(f.root), received.read_bytes(), os.lstat(received))
                with self.assertRaises(storage.StorageError) as caught:
                    parent.ensure_private_child('Received')
                self.assertIs(parent.initializations[-1]['error'], caught.exception)
                self.assertFalse(parent.initializations[-1]['called'])
                self.assertEqual(before[0], _directory_identity(f.root))
                self.assertEqual(before[1], received.read_bytes())
                after = os.lstat(received)
                self.assertEqual((before[2].st_dev, before[2].st_ino, before[2].st_mode),
                                 (after.st_dev, after.st_ino, after.st_mode))
            completed += 1

        self.assertEqual(7, completed)
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main()
