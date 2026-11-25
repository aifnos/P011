# -*- coding: utf-8 -*-
import os
import shutil
import stat
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime"))
from mta_storage import SafeZipReceiver, StorageError, TransferCancelled, validate_member_name


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="mta-host-storage-test-")
        self.root = os.path.join(self.base, "incoming")
        os.mkdir(self.root)
        self.archive = os.path.join(self.base, "input.zip")

    def tearDown(self):
        shutil.rmtree(self.base)

    def zip(self, members, compression=zipfile.ZIP_DEFLATED):
        with zipfile.ZipFile(self.archive, "w", compression=compression) as archive:
            for name, data in members:
                archive.writestr(name, data)
        return self.archive

    def receiver(self, **options):
        options.setdefault("reserve_bytes", 0)
        return SafeZipReceiver(self.root, **options)

    def assert_clean(self):
        self.assertEqual(os.listdir(self.root), [])

    def test_real_files_and_actual_progress(self):
        self.zip([("folder/", b""), ("folder/笔.txt", b"hello"), ("zero.bin", b"")])
        progress = []
        result = self.receiver().receive(self.archive, "task-1", progress=lambda done, total: progress.append((done, total)), expected_files=2, expected_bytes=5)
        self.assertEqual(result["fileCount"], 2)
        self.assertEqual(result["totalSize"], 5)
        self.assertEqual(progress[-1], (5, 5))
        self.assertTrue(all(os.path.isfile(path) for path in result["files"]))
        with open(result["files"][0], "rb") as source:
            self.assertEqual(source.read(), b"hello")
        self.assertTrue(os.path.isfile(self.archive))
        self.assertFalse(any(name.startswith(".mta-") for name in os.listdir(self.root)))

    def test_same_names_never_overwrite(self):
        existing = os.path.join(self.root, "song.txt")
        with open(existing, "wb") as target:
            target.write(b"owner data")
        self.zip([("song.txt", b"incoming")])
        first = self.receiver().receive(self.archive, "a")
        second = self.receiver().receive(self.archive, "b")
        self.assertNotEqual(first["directory"], second["directory"])
        with open(existing, "rb") as source:
            self.assertEqual(source.read(), b"owner data")

    def test_path_traversal_and_platform_unsafe_names(self):
        for name in ("../escape", "a/../../escape", "/absolute", "C:/foo", "a\\b", "a//b", "a/./b", "NUL", "COM1.txt", "name.", "name ", "x:stream", "a\x00b", "a\nb", "/", "a/" * 17 + "file"):
            with self.assertRaises(StorageError, msg=repr(name)):
                validate_member_name(name)
        self.zip([("../escape", b"payload")])
        with self.assertRaises(StorageError):
            self.receiver().receive(self.archive, "test")
        self.assert_clean()
        self.assertFalse(os.path.exists(os.path.join(self.base, "escape")))

    def test_symlink_member(self):
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.zip([(info, b"../outside")])
        with self.assertRaises(StorageError):
            self.receiver().receive(self.archive, "test")
        self.assert_clean()

    def test_special_file_member(self):
        info = zipfile.ZipInfo("fifo")
        info.create_system = 3
        info.external_attr = (stat.S_IFIFO | 0o600) << 16
        self.zip([(info, b"")])
        with self.assertRaises(StorageError):
            self.receiver().receive(self.archive, "test")
        self.assert_clean()

    def test_duplicate_and_case_collision(self):
        for members in ([('file', b'1'), ('file', b'2')], [('File', b'1'), ('file', b'2')], [('folder', b'1'), ('folder/x', b'2')], [('Folder/a', b'1'), ('folder/b', b'2')]):
            self.zip(members)
            with self.assertRaises(StorageError):
                self.receiver().receive(self.archive, "test")
            self.assert_clean()

    def test_count_and_size_limits(self):
        self.zip([("one", b"123"), ("two", b"456")])
        for options in ({"max_files": 1}, {"max_total_bytes": 5}, {"max_file_bytes": 2}):
            with self.assertRaises(StorageError):
                self.receiver(**options).receive(self.archive, "test")
            self.assert_clean()

    def test_space_checked(self):
        self.zip([("one", b"123")])
        with self.assertRaises(StorageError):
            self.receiver(free_space=lambda root: 2).receive(self.archive, "test")
        self.assert_clean()

    def test_space_exhausted_during_write(self):
        self.zip([("one", b"x" * 100000)])
        count = [0]
        def space(root):
            count[0] += 1
            return 1000000 if count[0] < 3 else 0
        with self.assertRaises(StorageError):
            self.receiver(free_space=space).receive(self.archive, "test")
        self.assert_clean()

    def test_request_does_not_substitute_for_result(self):
        self.zip([("one", b"123")])
        for options in ({"expected_files": 2}, {"expected_bytes": 4}):
            with self.assertRaises(StorageError):
                self.receiver().receive(self.archive, "test", **options)
            self.assert_clean()

    def test_cancel_before_receive(self):
        self.zip([("one", b"123")])
        with self.assertRaises(TransferCancelled):
            self.receiver().receive(self.archive, "test", cancelled=lambda: True)
        self.assert_clean()

    def test_cancel_during_receive_cleans_only_owned(self):
        existing = os.path.join(self.root, "owner.txt")
        with open(existing, "wb") as target:
            target.write(b"owner")
        self.zip([("one", b"x" * 200000)])
        cancel = [False]
        def progress(done, total):
            cancel[0] = True
        with self.assertRaises(TransferCancelled):
            self.receiver().receive(self.archive, "test", cancelled=lambda: cancel[0], progress=progress)
        self.assertEqual(os.listdir(self.root), ["owner.txt"])
        self.assertTrue(os.path.isfile(self.archive))

    def test_crc_corruption_never_commits(self):
        self.zip([("one", b"unique data 1234567")], zipfile.ZIP_STORED)
        with open(self.archive, "rb") as source:
            data = source.read()
        data = data.replace(b"unique data 1234567", b"changed dat 1234567", 1)
        with open(self.archive, "wb") as target:
            target.write(data)
        with self.assertRaises(StorageError):
            self.receiver().receive(self.archive, "test")
        self.assert_clean()

    def test_central_directory_bounded_before_zipfile(self):
        self.zip([("one", b"123")])
        with open(self.archive, "r+b") as archive:
            archive.seek(-22 + 10, 2)
            archive.write(struct.pack("<H", 5000))
        with self.assertRaises(StorageError):
            self.receiver().receive(self.archive, "test")
        self.assert_clean()

    def test_empty_archive_and_unsupported_compression(self):
        for members, compression in (([], zipfile.ZIP_STORED), ([("x", b"123")], zipfile.ZIP_BZIP2)):
            self.zip(members, compression)
            with self.assertRaises(StorageError):
                self.receiver().receive(self.archive, "test")
            self.assert_clean()

    def test_root_requires_explicit_subdirectory(self):
        for root in ("relative", os.path.join(self.base, "missing"), os.path.abspath(os.sep), os.path.expanduser("~")):
            with self.assertRaises(StorageError):
                SafeZipReceiver(root)

    def test_symlink_root_if_host_supports(self):
        link = os.path.join(self.base, "link")
        try:
            os.symlink(self.root, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("host symlink creation unavailable")
        with self.assertRaises(StorageError):
            SafeZipReceiver(link)


if __name__ == "__main__":
    unittest.main()
