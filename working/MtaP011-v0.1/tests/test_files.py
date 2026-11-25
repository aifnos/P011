import os
import pathlib
import sys
import tempfile
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'runtime'))
from mta_files import FileRegistry

class FileTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name)
        (self.root/'Text').mkdir();(self.root/'Text/a.txt').write_bytes(b'abc')
        self.registry=FileRegistry(str(self.root))
    def tearDown(self):self.temp.cleanup()
    def test_opaque_select(self):
        files=self.registry.list_files();self.assertEqual(files[0]['name'],'Text/a.txt')
        with self.registry.open_selection([files[0]['id']]) as selection:
            self.assertEqual(selection.total_bytes,3);self.assertEqual(selection.entries[0]['handle'].read(),b'abc')
        self.assertTrue(selection.closed)
    def test_no_paths_or_duplicates(self):
        files=self.registry.list_files()
        for ids in [['Text/a.txt'],['../etc/passwd'],[files[0]['id']]*2,[]]:
            with self.assertRaises(ValueError):self.registry.open_selection(ids)
    def test_modified(self):
        file=self.registry.list_files()[0];(self.root/'Text/a.txt').write_bytes(b'changed')
        with self.assertRaises(ValueError):self.registry.open_selection([file['id']])
    def test_symlink(self):
        try:os.symlink(str(self.root/'Text/a.txt'),str(self.root/'Text/link.txt'))
        except (OSError,NotImplementedError):self.skipTest('HOST does not allow creating symlinks')
        self.assertEqual(len(self.registry.list_files()),1)

if __name__=='__main__':unittest.main()
