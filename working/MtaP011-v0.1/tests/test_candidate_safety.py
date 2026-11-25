"""HOST manifest tests. Directory ownership tests here are not device evidence."""
import hashlib
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime'))
import mta_safety


class CandidateManifestTests(unittest.TestCase):
    def candidate(self, rows):
        area=Path(self.temp.name).as_posix()
        lines=[]
        for name,content in rows:
            lines.append('%s %d %s\n'%(hashlib.sha256(content).hexdigest(),len(content),name))
        raw=''.join(lines).encode('ascii')
        base=Path(area)/'candidates'/('mta-01-'+hashlib.sha256(raw).hexdigest()[:16])
        base.mkdir(parents=True,exist_ok=True)
        for name,content in rows:
            if any(part in ('.','..','') for part in name.split('/')):continue
            path=base/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content)
        (base/'SOURCE.sha256').write_bytes(raw)
        return area,base

    def setUp(self):self.temp=tempfile.TemporaryDirectory(prefix='mta-host-manifest-')
    def tearDown(self):self.temp.cleanup()

    def check(self, rows, extra=None):
        area,base=self.candidate(rows)
        if extra:(base/extra).write_bytes(b'EXTRA')
        # This isolated verifier test replaces only the Linux directory gate.
        # Real owned_directory is exercised by the explicit P011 trial.
        with mock.patch.object(mta_safety,'AREA',area),mock.patch.object(mta_safety,'owned_directory',lambda path:path):
            return mta_safety.verify_candidate(base.as_posix())

    def test_core_and_versioned_integration(self):
        value=self.check([('runtime/mta_service.py',b'CORE'),
                          ('integration/ToolboxMta-v0.1/device/MtaEmbedded.qml',b'UI'),
                          ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_server.py',b'SERVER'),
                          ('integration/ToolboxMta-v0.1/web/favicon.svg',b'ICON')])
        self.assertEqual(len(value),64)

    def test_arbitrary_nested_folder_rejected(self):
        with self.assertRaises(ValueError):self.check([('integration/Other/runtime/module.py',b'NO')])

    def test_private_assets_not_permitted(self):
        with self.assertRaises(ValueError):self.check([('integration/ToolboxMta-v0.1/private/secret',b'NO')])

    def test_extra_file_rejected(self):
        with self.assertRaises(ValueError):self.check([('runtime/core.py',b'OK')],extra='unlisted.txt')

    def test_duplicate_rejected(self):
        with self.assertRaises(ValueError):self.check([('runtime/core.py',b'OK'),('runtime/core.py',b'OK')])

    def test_member_limit(self):
        with self.assertRaises(ValueError):self.check([('runtime/f%03d.py'%i,b'OK') for i in range(97)])

    def test_dot_path_rejected(self):
        with self.assertRaises(ValueError):self.check([('runtime/..',b'NO')])

    def test_wrong_identity_rejected(self):
        area,base=self.candidate([('runtime/core.py',b'OK')])
        (base/'SOURCE.sha256').write_bytes(b'corrupt\n')
        with mock.patch.object(mta_safety,'AREA',area),mock.patch.object(mta_safety,'owned_directory',lambda path:path):
            with self.assertRaises(ValueError):mta_safety.verify_candidate(base.as_posix())


if __name__=='__main__':unittest.main()
