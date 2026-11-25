"""Host-only native launcher gates; no ADB, live /proc scan, or device writes."""
import hashlib
import os
import pathlib
import struct
import sys
import tempfile
import unittest
import zlib
from unittest import mock

BASE=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'runtime'))
import native_safety as safety
from native_session import preview_fixture_png


class NativeGateTests(unittest.TestCase):
    def baseline(self):
        return {'hashes':dict(safety.PINS),'processes':[
            {'name':'Z03','exe':'/usr/bin/Z03'},
            {'name':'control_engine','exe':'/usr/bin/control_engine'},
            {'name':'weston','exe':'/usr/bin/weston'}]}
    def test_requires_original_hash_and_single_process(self):
        with mock.patch('native_safety.os.path.lexists',return_value=False):
            safety.require_stock(self.baseline())
            bad=self.baseline();bad['hashes']['/usr/bin/Z03']='0'*64
            with self.assertRaises(ValueError):safety.require_stock(bad)
            bad=self.baseline();bad['processes'].append(dict(bad['processes'][0]))
            with self.assertRaises(ValueError):safety.require_stock(bad)
            bad=self.baseline();bad['processes'][0]['exe']='/tmp/Z03-candidate'
            with self.assertRaises(ValueError):safety.require_stock(bad)
    def test_existing_temporary_menu_rejected(self):
        with mock.patch('native_safety.os.path.lexists',return_value=True):
            with self.assertRaises(ValueError):safety.require_stock(self.baseline())
    def test_fixture_png_crc_and_scanlines(self):
        image=preview_fixture_png();self.assertEqual(image[:8],b'\x89PNG\r\n\x1a\n')
        pos=8;parts={}
        while pos<len(image):
            length=struct.unpack('!I',image[pos:pos+4])[0];name=image[pos+4:pos+8]
            data=image[pos+8:pos+8+length];crc=struct.unpack('!I',image[pos+8+length:pos+12+length])[0]
            self.assertEqual(zlib.crc32(name+data)&0xffffffff,crc);parts[name]=data;pos+=12+length
        self.assertEqual(struct.unpack('!II',parts[b'IHDR'][:8]),(144,64))
        self.assertEqual(len(zlib.decompress(parts[b'IDAT'])),64*(144*3+1))
    @unittest.skipIf(os.name=='nt','POSIX path gates are tested in WSL and on the pen')
    def test_candidate_identity_and_no_unlisted_files(self):
        with tempfile.TemporaryDirectory(prefix='p011-native-gate-') as root,mock.patch.object(safety,'AREA',root):
            source=b'print("fixture")\n'
            manifest=(hashlib.sha256(source).hexdigest()+' '+str(len(source))+' runtime/fixture.py\n').encode()
            identity=hashlib.sha256(manifest).hexdigest()
            base=root+'/candidates/native-051-'+identity[:16]
            safety.owned_directory(base+'/runtime',True)
            pathlib.Path(base,'runtime/fixture.py').write_bytes(source)
            pathlib.Path(base,'SOURCE.sha256').write_bytes(manifest)
            self.assertEqual(safety.verify_candidate(base),identity)
            pathlib.Path(base,'unexpected.txt').write_text('x')
            with self.assertRaises(ValueError):safety.verify_candidate(base)
    @unittest.skipIf(os.name=='nt','POSIX symlink gates are tested in WSL and on the pen')
    def test_directory_rejects_escape_and_symlink(self):
        with tempfile.TemporaryDirectory(prefix='p011-native-gate-') as root,mock.patch.object(safety,'AREA',root):
            with self.assertRaises(ValueError):safety.owned_directory('/etc',True)
            with self.assertRaises(ValueError):safety.owned_directory(root+'/../other',True)
            os.symlink('/tmp',root+'/redirect')
            with self.assertRaises(ValueError):safety.owned_directory(root+'/redirect/should-not-exist',True)


if __name__=='__main__':unittest.main(verbosity=2)
