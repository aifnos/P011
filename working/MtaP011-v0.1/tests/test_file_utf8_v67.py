# -*- coding: utf-8 -*-
"""Six new UTF-8 path tests, not a radio/phone or P011 acceptance test.

Only the v67 storage/registry definitions are executed. A PRIVATE per-domain
ASCII path adapter rejects non-ASCII str syscall inputs, strictly translates
valid UTF-8 bytes to real HOST temporary-filesystem paths, and delegates file
bytes/FDs/ZIP CRCs to the actual standard library. It does not change os,
sys.modules, filesystem locale, source gates, quotas or resource accounting.
Invalid UTF-8 enumeration is explicitly modeled because Windows filenames
cannot represent arbitrary POSIX bytes. FileStore readback is the unchanged
HOST implementation; it is not evidence for P011's descriptor-based branch.
"""
import builtins
import errno
import hashlib
import os
import shutil
import sys
import tempfile
import types
import unittest
import zipfile


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES = (
    ('p011_json', 'runtime/p011_json.py',
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88', 8061),
    ('mta_protocol', 'runtime/mta_protocol.py',
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57', 17958),
    ('mta_storage', 'candidate/file-utf8-v67/runtime/mta_storage.py',
     '9bcc905c8cc44400a83ad5d4f0a2fc9dafb8d28c36ba40f76e7ce9cdc3857afb', 15161),
    ('mta_files', 'candidate/file-utf8-v67/runtime/mta_files.py',
     'c6316be40cf34f017d1d2160f48989a55edfa0a60a2abe6a2ff6b656773f752b', 10987),
    ('mta_toolbox_storage', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py',
     'd9fa92a795729d88f6fac27705a2883adba8aac72423b4ebcd9220ffb78ddb51', 9114),
)


class _PathAdapter(object):
    def __init__(self, owner):
        self.owner = owner

    def __getattr__(self, name):
        return getattr(os.path, name)

    def _query(self, name, path):
        return getattr(os.path, name)(self.owner.actual(path, 'path.' + name))

    def isdir(self, path):
        return self._query('isdir', path)

    def isfile(self, path):
        return self._query('isfile', path)

    def islink(self, path):
        return self._query('islink', path)

    def lexists(self, path):
        return self._query('lexists', path)

    def getsize(self, path):
        return self._query('getsize', path)


class _AsciiFilesystem(object):
    """Private syscall boundary, not a POSIX implementation or OS success stub."""
    def __init__(self, mode='posix'):
        self.name = mode
        self.sep = os.sep
        self.path = _PathAdapter(self)
        self.calls = []
        self.opened = []
        self.mkdtemps = []
        self.removed = []
        self.walk_paths = []
        self.inject_invalid = False
        self.invalid_pruned = []
        self.invalid_calls = 0
        self.created_output = []

    def __getattr__(self, name):
        return getattr(os, name)

    def actual(self, path, operation):
        self.calls.append((operation, path))
        if isinstance(path, bytes):
            try:
                return path.decode('utf-8')
            except UnicodeDecodeError:
                self.invalid_calls += 1
                raise
        if isinstance(path, str):
            if self.name == 'posix':
                path.encode('ascii')  # Intentionally expose locale-dependent calls.
            return path
        if type(path) is int:
            return path
        raise TypeError('model path must be a str/bytes or existing FD')

    def open(self, path, flags, mode=0o777):
        actual = self.actual(path, 'os.open')
        fd = os.open(actual, flags, mode)
        self.opened.append((path, fd, flags, mode))
        if flags & os.O_CREAT:
            self.created_output.append(actual)
        return fd

    def lstat(self, path):
        return os.lstat(self.actual(path, 'os.lstat'))

    def chmod(self, path, mode):
        return os.chmod(self.actual(path, 'os.chmod'), mode)

    def makedirs(self, path, mode=0o777, exist_ok=False):
        return os.makedirs(self.actual(path, 'os.makedirs'), mode=mode, exist_ok=exist_ok)

    def rename(self, source, target):
        return os.rename(self.actual(source, 'os.rename.source'),
                         self.actual(target, 'os.rename.target'))

    def builtin_open(self, path, *args, **kwargs):
        return builtins.open(self.actual(path, 'builtin.open'), *args, **kwargs)

    def disk_usage(self, path):
        return shutil.disk_usage(self.actual(path, 'shutil.disk_usage'))

    def rmtree(self, path):
        actual = self.actual(path, 'shutil.rmtree')
        self.removed.append(actual)
        return shutil.rmtree(actual)

    def mkdtemp(self, prefix=None, suffix=None, dir=None):
        if prefix is None or dir is None or type(prefix) is not type(dir):
            raise TypeError('modeled tempfile requires same-type explicit prefix and dir')
        if suffix is not None and type(suffix) is not type(dir):
            raise TypeError('mixed tempfile pathname types')
        actual_prefix = self.actual(prefix, 'tempfile.prefix')
        actual_dir = self.actual(dir, 'tempfile.dir')
        actual_suffix = '' if suffix is None else self.actual(suffix, 'tempfile.suffix')
        generated = tempfile.mkdtemp(prefix=actual_prefix, suffix=actual_suffix, dir=actual_dir)
        self.mkdtemps.append((prefix, dir, generated))
        return generated.encode('utf-8') if isinstance(dir, bytes) else generated

    def walk(self, top, followlinks=False):
        actual_top = self.actual(top, 'os.walk')
        if followlinks:
            raise AssertionError('unexpected modeled followlinks')
        for directory, directories, files in os.walk(actual_top, followlinks=False):
            self.walk_paths.append(directory)
            if isinstance(top, bytes):
                native_directory = directory.encode('utf-8')
                native_dirs = [name.encode('utf-8') for name in directories]
                native_files = [name.encode('utf-8') for name in files]
            elif self.name == 'nt':
                native_directory = directory
                native_dirs = list(directories)
                native_files = list(files)
            else:
                native_directory = directory
                native_dirs = [name.encode('utf-8').decode('ascii', 'surrogateescape')
                               for name in directories]
                native_files = [name.encode('utf-8').decode('ascii', 'surrogateescape')
                                for name in files]
            injected = self.inject_invalid and isinstance(top, bytes) and directory == actual_top
            if injected:
                native_dirs.append(b'\xff-invalid-directory')
                native_files.append(b'\xff-invalid.txt')
            yield native_directory, native_dirs, native_files
            if injected:
                self.invalid_pruned.append(b'\xff-invalid-directory' not in native_dirs)
            # Mirror actual os.walk's pruning, without inventing native files.
            retained = []
            for native in native_dirs:
                try:
                    name = (native.decode('utf-8') if isinstance(native, bytes)
                            else native.encode('ascii', 'surrogateescape').decode('utf-8'))
                except UnicodeError:
                    continue
                if name in directories:
                    retained.append(name)
            directories[:] = retained


def _load_domain(filesystem):
    """Execute pinned definitions in an isolated import dictionary, never sys.modules."""
    modules = {}
    snapshots = dict(sys.modules)
    os_name = os.name
    filesystem_encoding = sys.getfilesystemencoding()
    for name, relative, expected_hash, expected_size in SOURCES:
        path = os.path.join(ROOT, *relative.split('/'))
        with builtins.open(path, 'rb') as handle:
            raw = handle.read()
        if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != expected_hash:
            raise AssertionError('fixed UTF8 definition identity changed')
        module = types.ModuleType(name)
        module.__file__ = path
        private_builtins = dict(vars(builtins))
        original_import = builtins.__import__

        def importing(import_name, globals=None, locals=None, fromlist=(), level=0,
                      _name=name, _original=original_import):
            if level == 0 and import_name in modules:
                return modules[import_name]
            if _name in ('mta_storage', 'mta_files'):
                if import_name == 'os':
                    return filesystem
                if import_name == 'shutil':
                    return types.SimpleNamespace(disk_usage=filesystem.disk_usage,
                                                 rmtree=filesystem.rmtree)
                if import_name == 'tempfile':
                    return types.SimpleNamespace(mkdtemp=filesystem.mkdtemp)
            return _original(import_name, globals, locals, fromlist, level)

        private_builtins['__import__'] = importing
        if name == 'mta_storage':
            private_builtins['open'] = filesystem.builtin_open
        module.__dict__['__builtins__'] = private_builtins
        exec(compile(raw.decode('utf-8'), name + '@' + expected_hash, 'exec'), module.__dict__)
        modules[name] = module
    for name in modules:
        if sys.modules.get(name) is not snapshots.get(name):
            raise AssertionError('definition load changed an external module domain')
    if os.name != os_name or sys.getfilesystemencoding() != filesystem_encoding:
        raise AssertionError('definition load changed global OS/locale state')
    return modules


class FileUtf8V67Tests(unittest.TestCase):
    completed = 0

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='p011-host67-private-')
        self.addCleanup(self.temp.cleanup)
        self.parent = self.temp.name
        self.root = os.path.join(self.parent, '中文用户目录')
        os.mkdir(self.root)
        for category in ('Music', 'Pictures', 'Text', 'GameResources', 'Screenshots', 'Exports', 'Received'):
            os.mkdir(os.path.join(self.root, category))
        self.fs = _AsciiFilesystem()
        self.modules = _load_domain(self.fs)
        self.storage = self.modules['mta_storage']
        self.files = self.modules['mta_files']

    def write_file(self, relative, contents):
        path = os.path.join(self.root, *relative.split('/'))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with builtins.open(path, 'wb') as handle:
            handle.write(contents)
        return path

    def zip_file(self, filename='中文压缩包.zip', entries=None):
        path = os.path.join(self.parent, filename)
        if entries is None:
            entries = [('资料/说明.txt', '收到的中文内容\n'.encode('utf-8')),
                       ('图片/样本.bin', b'\x00\x01\x02binary')]
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, contents in entries:
                archive.writestr(name, contents)
        return path, entries

    def receiver(self):
        return self.storage.SafeZipReceiver(os.path.join(self.root, 'Received'),
                                            max_files=8, max_total_bytes=4 * 1024 * 1024,
                                            max_file_bytes=2 * 1024 * 1024, reserve_bytes=0)

    def assert_valid_text(self, value):
        self.assertIs(type(value), str)
        self.assertEqual(value, value.encode('utf-8').decode('utf-8'))

    def assert_native_boundary(self):
        self.assertEqual(0, self.fs.invalid_calls)
        seen_unicode = False
        for operation, path in self.fs.calls:
            if isinstance(path, bytes):
                actual = path.decode('utf-8')
                if any(ord(char) > 127 for char in actual):
                    seen_unicode = True
            elif isinstance(path, str):
                path.encode('ascii')
        self.assertTrue(seen_unicode)

    def finish_method(self):
        type(self).completed += 1

    @classmethod
    def tearDownClass(cls):
        if cls.completed == 6:
            print('HOST67_FILE_UTF8 new_methods=6 old_methods=0 simulated_ascii=true device=false phone=false')

    def test_encoding_modes_and_strict_public_paths(self):
        name = '目录/文件.txt'
        native = self.storage.native_name(name)
        self.assertIs(type(native), bytes)
        self.assertEqual(name.encode('utf-8'), native)
        self.assertEqual(name, self.storage._public_name(native))
        with self.assertRaises(UnicodeEncodeError):
            self.fs.actual(name, 'fixture.ASCII-rejection')
        # This failed request is fixture-only, not candidate IO.
        self.fs.calls.pop()
        with self.assertRaises(UnicodeDecodeError):
            self.storage._public_name(b'\xff')
        with self.assertRaises(UnicodeEncodeError):
            self.storage.native_name('\udcff')
        with self.assertRaises(ValueError):
            self.storage.validate_member_name('../中文.txt')
        windows = _AsciiFilesystem(mode='nt')
        windows_modules = _load_domain(windows)
        value = windows_modules['mta_storage'].native_name(name)
        self.assertIs(value, name)
        windows_registry = windows_modules['mta_files'].FileRegistry(self.root)
        path = self.write_file('Text/原生字符串.txt', b'windows-str-path')
        rows = windows_registry.list_files()
        self.assertEqual(['Text/原生字符串.txt'], [row['name'] for row in rows])
        selection = windows_registry.open_selection([rows[0]['id']])
        self.addCleanup(selection.close)
        self.assertEqual(b'windows-str-path', selection.entries[0]['handle'].read())
        selection.close()
        self.assertTrue(selection.lifecycle_status()['closure_verified'])
        self.assertTrue(all(type(item[0]) is str for item in windows.opened))
        self.assertTrue(os.path.isfile(path))
        self.assertEqual('nt', windows.name)
        self.assertEqual('posix', self.fs.name)
        self.finish_method()

    def test_chinese_catalog_selection_actual_bytes_and_close(self):
        contents = '音乐名和文本内容\n'.encode('utf-8') + b'\x00tail'
        path = self.write_file('Text/中文资料/测试文件.txt', contents)
        self.write_file('Text/.隐藏.txt', b'hidden')
        self.write_file('Other/不可见.txt', b'outside-whitelist')
        registry = self.files.FileRegistry(self.root)
        rows = registry.list_files()
        self.assertEqual(['Text/中文资料/测试文件.txt'], [row['name'] for row in rows])
        row = rows[0]
        self.assert_valid_text(row['name'])
        self.assertRegex(row['id'], r'^[0-9a-f]{32}$')
        self.assertNotIn('中文', row['id'])
        self.assertEqual(len(contents), row['size'])
        self.assertEqual(rows, registry.list_files())  # Original signature/opaque ID retained.
        selection = registry.open_selection([row['id']])
        self.addCleanup(selection.close)
        resource = selection._resources[0]
        fd = resource.fd
        self.assertEqual(row['name'], selection.entries[0]['name'])
        self.assertEqual(contents, selection.entries[0]['handle'].read())
        self.assertEqual(len(contents), selection.total_bytes)
        self.assertEqual(os.stat(path).st_ino, os.fstat(fd).st_ino)
        selection.close()
        status = selection.lifecycle_status()
        self.assertTrue(status['closure_verified'])
        self.assertFalse(status['resource_pending'])
        self.assertEqual((1, 1, 1), (status['close_attempted_count'],
                                    status['wrapper_closed_count'], status['fd_closed_count']))
        self.assertTrue(resource.attempted and resource.verified)
        with self.assertRaises(OSError) as observed:
            os.fstat(fd)
        self.assertEqual(errno.EBADF, observed.exception.errno)
        before = status.copy()
        selection.close()
        self.assertEqual(before, selection.lifecycle_status())
        self.assertFalse(registry.lifecycle_status()['resource_pending'])
        self.assertTrue(all(type(pathname) is bytes for pathname, unused, flags, mode in self.fs.opened))
        self.assert_native_boundary()
        self.finish_method()

    def test_chinese_zip_receive_registry_and_unchanged_file_center(self):
        zip_path, entries = self.zip_file()
        progress = []
        result = self.receiver().receive(zip_path, 'utf8-receive',
                                         progress=lambda actual, total: progress.append((actual, total)),
                                         expected_files=len(entries),
                                         expected_bytes=sum(len(body) for name, body in entries))
        self.assertEqual('utf8-receive', result['taskId'])
        self.assert_valid_text(result['directory'])
        self.assertEqual(2, result['fileCount'])
        self.assertEqual(sum(len(body) for name, body in entries), result['totalSize'])
        self.assertEqual(result['totalSize'], progress[-1][0])
        self.assertTrue(os.path.isfile(zip_path))
        registry = self.files.FileRegistry(self.root)
        rows = registry.list_files()
        expected = {}
        for name, body in entries:
            path = os.path.join(result['directory'], *name.split('/'))
            self.assertIn(path, result['files'])
            self.assert_valid_text(path)
            expected[os.path.relpath(path, self.root).replace(os.sep, '/')] = body
        self.assertEqual(set(expected), set(row['name'] for row in rows))
        with registry.open_selection([row['id'] for row in rows]) as selection:
            for selected in selection.entries:
                self.assertEqual(expected[selected['name']], selected['handle'].read())
        self.assertFalse(registry.lifecycle_status()['resource_pending'])
        file_store = self.modules['mta_toolbox_storage'].FileStore(self.root)
        self.addCleanup(file_store.close)
        for relative, body in expected.items():
            handle, metadata = file_store.open_file(relative)
            with handle:
                self.assertEqual(body, handle.read())
            self.assertEqual(len(body), metadata.st_size)
        text_path = next(path for path in expected if path.endswith('.txt'))
        self.assertEqual(expected[text_path].decode('utf-8'), file_store.text(text_path)['text'])
        parent = text_path.rsplit('/', 1)[0]
        listing = file_store.listing(parent)
        self.assertIn(text_path, [row['path'] for row in listing['entries']])
        file_store.close()
        self.assertIsNone(file_store.rootfd)
        self.assertTrue(self.fs.mkdtemps)
        self.assertTrue(all(type(prefix) is bytes and type(directory) is bytes
                            for prefix, directory, generated in self.fs.mkdtemps))
        self.assertTrue(all(flags & os.O_EXCL for path, fd, flags, mode in self.fs.opened
                            if flags & os.O_CREAT))
        self.assertTrue(all(mode == 0o600 for path, fd, flags, mode in self.fs.opened
                            if flags & os.O_CREAT))
        self.assert_native_boundary()
        self.finish_method()

    def test_same_chinese_filename_never_overwrites_existing_namespace(self):
        existing = self.write_file('Received/资料/同名.txt', b'existing-user-file')
        zip_path, entries = self.zip_file(entries=[('资料/同名.txt', b'first-new-file')])
        receiver = self.receiver()
        first = receiver.receive(zip_path, 'first-receive', expected_files=1, expected_bytes=14)
        second = receiver.receive(zip_path, 'second-receive', expected_files=1, expected_bytes=14)
        self.assertNotEqual(first['directory'], second['directory'])
        self.assertNotEqual(first['files'], second['files'])
        self.assertEqual(os.path.join(self.root, 'Received'), os.path.dirname(first['directory']))
        self.assertEqual(os.path.join(self.root, 'Received'), os.path.dirname(second['directory']))
        for result in (first, second):
            self.assert_valid_text(result['directory'])
            with builtins.open(result['files'][0], 'rb') as handle:
                self.assertEqual(b'first-new-file', handle.read())
        with builtins.open(existing, 'rb') as handle:
            self.assertEqual(b'existing-user-file', handle.read())
        self.assertTrue(os.path.isfile(zip_path))
        self.assertEqual(3, len(self.files.FileRegistry(self.root).list_files()))
        self.assertTrue(all(not name.startswith('.mta-stage-')
                            for name in os.listdir(os.path.join(self.root, 'Received'))))
        self.assert_native_boundary()
        self.finish_method()

    def test_cancel_after_chinese_member_write_removes_only_owned_staging(self):
        retained = self.write_file('Received/原有目录/保留.txt', b'must-remain')
        zip_path, entries = self.zip_file(entries=[('中文目录/取消文件.txt', b'Z' * 100000)])
        zip_hash = self.hash_file(zip_path)
        receive_root = os.path.join(self.root, 'Received')
        original_names = set(os.listdir(receive_root))
        state = {'cancelled': False, 'written': False}

        def progress(actual, total):
            self.assertGreater(actual, 0)
            self.assertEqual(100000, total)
            self.assertTrue(self.fs.created_output)
            self.assertTrue(os.path.isfile(self.fs.created_output[-1]))
            state['written'] = True
            state['cancelled'] = True

        with self.assertRaises(self.storage.TransferCancelled):
            self.receiver().receive(zip_path, 'cancel-utf8',
                                    cancelled=lambda: state['cancelled'], progress=progress,
                                    expected_files=1, expected_bytes=100000)
        self.assertTrue(state['written'])
        self.assertEqual(original_names, set(os.listdir(receive_root)))
        self.assertEqual(1, len(self.fs.mkdtemps))
        created = self.fs.mkdtemps[0][2]
        self.assertEqual([created], self.fs.removed)
        self.assertFalse(os.path.exists(created))
        self.assertTrue(all(not os.path.exists(path) for path in self.fs.created_output))
        self.assertEqual(zip_hash, self.hash_file(zip_path))
        with builtins.open(retained, 'rb') as handle:
            self.assertEqual(b'must-remain', handle.read())
        self.assert_native_boundary()
        self.finish_method()

    def hash_file(self, path):
        with builtins.open(path, 'rb') as handle:
            return hashlib.sha256(handle.read()).digest()

    def test_invalid_utf8_enumerated_names_are_pruned_not_surrogate_published(self):
        body = b'valid-neighbor'
        self.write_file('Text/有效目录/中文.txt', body)
        self.write_file('Text/.隐藏目录/隐藏.txt', b'hidden')
        self.fs.inject_invalid = True
        registry = self.files.FileRegistry(self.root)
        rows = registry.list_files()
        self.assertEqual(['Text/有效目录/中文.txt'], [row['name'] for row in rows])
        self.assertEqual(0, self.fs.invalid_calls)
        self.assertTrue(self.fs.invalid_pruned)
        self.assertTrue(all(self.fs.invalid_pruned))
        self.assertFalse(any('.隐藏目录' in path for path in self.fs.walk_paths))
        self.assertTrue(all(type(path) is bytes for operation, path in self.fs.calls
                            if operation == 'os.walk'))
        for row in rows:
            self.assert_valid_text(row['name'])
            self.assert_valid_text(row['id'])
        self.assertEqual(rows, registry.list_files())
        with registry.open_selection([rows[0]['id']]) as selection:
            self.assertEqual(body, selection.entries[0]['handle'].read())
        self.assertFalse(registry.lifecycle_status()['resource_pending'])
        self.assert_native_boundary()
        self.finish_method()


if __name__ == '__main__':
    unittest.main(verbosity=0)
